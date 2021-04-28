/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.lldb.manager.impl;

import static ghidra.async.AsyncUtils.sequence;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Pair;

import com.sun.jna.platform.win32.COM.COMException;

import SWIG.SBProcess;
import SWIG.SBTarget;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugBreakpoint;
import agent.lldb.lldb.DebugBreakpoint.BreakFlags;
import agent.lldb.lldb.DebugBreakpoint.BreakType;
import agent.lldb.lldb.DebugProcessId;
import agent.lldb.lldb.DebugSessionId;
import agent.lldb.lldb.DebugThreadId;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.LldbEventsListener;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.LldbStateListener;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.manager.breakpoint.LldbBreakpointType;
import ghidra.async.AsyncClaimQueue;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.gadp.protocol.Gadp.ExecutionState;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.HandlerMap;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class LldbManagerImpl implements LldbManager {

	private String dbgSrvTransport;

	//private final AsyncClaimQueue<DebugThreadInfo> claimsCreateThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugThreadId> claimsContinueThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugThreadId> claimsStopThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<ExitEvent> claimsExitThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugModuleInfo> claimsLoadModule = new AsyncClaimQueue<>();
	private final AsyncClaimQueue<DebugThreadId> claimsBreakpointAdded = new AsyncClaimQueue<>();
	private final AsyncClaimQueue<BreakId> claimsBreakpointRemoved = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugThreadId> claimsFocusThread = new AsyncClaimQueue<>();

	public DebugStatus status;

	public final Set<DebugStatus> statiAccessible =
		Collections.unmodifiableSet(EnumSet.of(DebugStatus.NO_DEBUGGEE, DebugStatus.BREAK));

	private final Map<Integer, BreakpointTag> breaksById = new LinkedHashMap<>();

	protected AbstractClientThreadExecutor engThread;
	protected DebugClientReentrant reentrantClient;

	private List<DbgPendingCommand<?>> activeCmds = new ArrayList<>();

	protected final Map<DebugSessionId, SBTarget> sessions = new LinkedHashMap<>();
	protected SBTarget curSession = null;
	private final Map<DebugSessionId, SBTarget> unmodifiableSessions =
		Collections.unmodifiableMap(sessions);

	protected final Map<DebugProcessId, SBProcess> processes = new LinkedHashMap<>();
	private final Map<DebugProcessId, SBProcess> unmodifiableProcesses =
		Collections.unmodifiableMap(processes);

	protected final Map<DebugThreadId, SBThread> threads = new LinkedHashMap<>();
	private final Map<DebugThreadId, SBThread> unmodifiableThreads =
		Collections.unmodifiableMap(threads);

	private final Map<Long, LldbBreakpointInfo> breakpoints = new LinkedHashMap<>();
	private final Map<Long, LldbBreakpointInfo> unmodifiableBreakpoints =
		Collections.unmodifiableMap(breakpoints);

	protected final AsyncReference<StateType, LldbCause> state =
		new AsyncReference<>(StateType.NOT_STARTED);
	private final HandlerMap<LldbEvent<?>, Void, DebugStatus> handlerMap = new HandlerMap<>();
	private final Map<Class<?>, DebugStatus> statusMap = new LinkedHashMap<>();
	private final Map<String, DebugStatus> statusByNameMap = new LinkedHashMap<>();
	private final ListenerSet<LldbEventsListener> listenersEvent =
		new ListenerSet<>(LldbEventsListener.class);

	private DebugEventInformation lastEventInformation;
	private SBTarget currentSession;
	private SBProcess currentProcess;
	private SBThread currentThread;
	private SBTarget eventSession;
	private SBProcess eventProcess;
	private SBThread eventThread;
	private volatile boolean waiting = false;
	private boolean kernelMode = false;
	private CompletableFuture<String> continuation;

	/**
	 * Instantiate a new manager
	 */
	public LldbManagerImpl() {
		state.filter(this::stateFilter);
		state.addChangeListener(this::trackRunningInterpreter);
		defaultHandlers();
		//TODO: this.server = createSctlSide(addr);
		//TODO: this.dbgSrvTransport = dbgSrvTransport;
	}

	@Override
	public SBThread getThread(DebugThreadId tid) {
		synchronized (threads) {
			return threads.get(tid);
		}
	}

	public SBThreadImpl getThreadComputeIfAbsent(DebugThreadId id, SBProcess process,
			int tid) {
		synchronized (threads) {
			if (!threads.containsKey(id)) {
				SBThreadImpl thread = new SBThreadImpl(this, process, id, tid);
				thread.add();
			}
			return threads.get(id);
		}
	}

	/**
	 * Use {@link SBThreadImpl#remove()} instead
	 * 
	 * @param id the thread ID to remove
	 */
	public void removeThread(DebugThreadId id) {
		synchronized (threads) {
			if (threads.remove(id) == null) {
				throw new IllegalArgumentException("There is no thread with id " + id);
			}
		}
	}

	/**
	 * Use {@link SBProcessImpl#remove(LldbCause)} instead
	 * 
	 * @param id the process ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeProcess(DebugProcessId id, LldbCause cause) {
		synchronized (processes) {
			SBProcessImpl proc = processes.remove(id);
			if (proc == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			Set<DebugThreadId> toRemove = new HashSet<>();
			for (DebugThreadId tid : threads.keySet()) {
				SBThreadImpl thread = threads.get(tid);
				if (thread.getProcess().getId().equals(id)) {
					toRemove.add(tid);
				}
			}
			for (DebugThreadId tid : toRemove) {
				removeThread(tid);
			}
			getEventListeners().fire.processRemoved(id, cause);
		}
	}

	/**
	 * Update the selected process
	 * 
	 * @param process the process that now has focus
	 * @param cause the cause of the focus change
	 * @param fire signal listeners
	 * @return success status
	 */
	@Override
	public SBProcess getProcess(DebugProcessId id) {
		synchronized (processes) {
			SBProcessImpl result = processes.get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			return result;
		}
	}

	public SBProcess getProcessComputeIfAbsent(DebugProcessId id, int pid) {
		synchronized (processes) {
			if (!processes.containsKey(id)) {
				SBProcessImpl process = new SBProcessImpl(this, id, pid);
				process.add();
			}
			return processes.get(id);
		}
	}

	/**
	 * Use {@link SBTargetImpl#remove(LldbCause)} instead
	 * 
	 * @param id the session ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeSession(DebugSessionId id, LldbCause cause) {
		synchronized (sessions) {
			if (sessions.remove(id) == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			getEventListeners().fire.sessionRemoved(id, cause);
		}
	}

	@Override
	public SBTarget getSession(DebugSessionId id) {
		synchronized (sessions) {
			SBTarget result = sessions.get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			return result;
		}
	}

	public SBTarget getSessionComputeIfAbsent(DebugSessionId id) {
		synchronized (sessions) {
			if (!sessions.containsKey(id) && id.id >= 0) {
				SBTargetImpl session = new SBTargetImpl(this, id);
				session.add();
			}
			return sessions.get(id);
		}
	}

	@Override
	public Map<DebugThreadId, SBThread> getKnownThreads() {
		return unmodifiableThreads;
	}

	@Override
	public Map<DebugProcessId, SBProcess> getKnownProcesses() {
		return unmodifiableProcesses;
	}

	@Override
	public Map<DebugSessionId, SBTarget> getKnownSessions() {
		return unmodifiableSessions;
	}

	@Override
	public Map<Long, LldbBreakpointInfo> getKnownBreakpoints() {
		return unmodifiableBreakpoints;
	}

	private LldbBreakpointInfo addKnownBreakpoint(LldbBreakpointInfo bkpt, boolean expectExisting) {
		LldbBreakpointInfo old = breakpoints.put(bkpt.getNumber(), bkpt);
		if (expectExisting && old == null) {
			Msg.warn(this, "Breakpoint " + bkpt.getNumber() + " is not known");
		}
		else if (!expectExisting && old != null) {
			Msg.warn(this, "Breakpoint " + bkpt.getNumber() + " is already known");
		}
		return old;
	}

	private LldbBreakpointInfo getKnownBreakpoint(long number) {
		LldbBreakpointInfo info = breakpoints.get(number);
		if (info == null) {
			Msg.warn(this, "Breakpoint " + number + " is not known");
		}
		return info;
	}

	private LldbBreakpointInfo removeKnownBreakpoint(long number) {
		LldbBreakpointInfo del = breakpoints.remove(number);
		if (del == null) {
			Msg.warn(this, "Breakpoint " + number + " is not known");
		}
		return del;
	}

	@Override
	public CompletableFuture<LldbBreakpointInfo> insertBreakpoint(String loc,
			LldbBreakpointType type) {
		return execute(new LldbInsertBreakpointCommand(this, loc, type));
	}

	@Override
	public CompletableFuture<LldbBreakpointInfo> insertBreakpoint(long loc, int len,
			LldbBreakpointType type) {
		return execute(new LldbInsertBreakpointCommand(this, loc, len, type));
	}

	@Override
	public CompletableFuture<Void> disableBreakpoints(long... numbers) {
		return execute(new LldbDisableBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Void> enableBreakpoints(long... numbers) {
		return execute(new LldbEnableBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Void> deleteBreakpoints(long... numbers) {
		return execute(new LldbDeleteBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Map<Long, LldbBreakpointInfo>> listBreakpoints() {
		return execute(new LldbListBreakpointsCommand(this));
	}

	private void checkStarted() {
		if (state.get() == StateType.NOT_STARTED) {
			throw new IllegalStateException(
				"dbgeng has not been started or has not finished starting");
		}
	}

	@Override
	public CompletableFuture<Void> start(String[] args) {
		state.set(StateType.STARTING, Causes.UNCLAIMED);
		boolean create = true;
		if (args.length == 0) {
			engThread = new DbgEngClientThreadExecutor(() -> DbgEng.debugCreate().createClient());
		}
		else {
			String remoteOptions = String.join(" ", args);
			engThread = new DbgEngClientThreadExecutor(
				() -> DbgEng.debugConnect(remoteOptions).createClient());
			create = false;
		}
		engThread.setManager(this);
		AtomicReference<Boolean> creat = new AtomicReference<>(create);
		return sequence(TypeSpec.VOID).then(engThread, (seq) -> {
			doExecute(creat.get());
			seq.exit();
		}).finish().exceptionally((exc) -> {
			Msg.error(this, "start failed");
			return null;
		});
	}

	protected void doExecute(Boolean create) {
		DebugClient dbgeng = engThread.getClient();
		reentrantClient = dbgeng;

		status = dbgeng.getControl().getExecutionStatus();
		// Take control of the session.
		// Helps if the JVM is using it for SA, or when starting a new server during testing.
		if (create) {
			dbgeng.endSession(DebugEndSessionFlags.DEBUG_END_ACTIVE_TERMINATE);
		}

		status = dbgeng.getControl().getExecutionStatus();
		dbgeng.setOutputCallbacks(new DbgDebugOutputCallbacks(this));
		dbgeng.setEventCallbacks(new DbgDebugEventCallbacksAdapter(this));
		dbgeng.setInputCallbacks(new DbgDebugInputCallbacks(this));
		dbgeng.flushCallbacks();

		if (!create) {
			dbgeng.connectSession(0);
		}

		if (dbgSrvTransport != null && !"none".equalsIgnoreCase(dbgSrvTransport)) {
			dbgeng.startServer(dbgSrvTransport);
		}
	}

	@Override
	public boolean isRunning() {
		return !engThread.isShutdown() && !engThread.isTerminated();
	}

	@Override
	public void terminate() {
		//TODO: server.terminate();
		engThread.execute(100, dbgeng -> {
			Msg.debug(this, "Disconnecting DebugClient from session");
			dbgeng.endSession(DebugEndSessionFlags.DEBUG_END_DISCONNECT);
			dbgeng.setOutputCallbacks(null);
		});
		engThread.shutdown();
		try {
			engThread.awaitTermination(5000, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			// Eh, just go on
		}
	}

	@Override
	public void close() throws Exception {
		terminate();
	}

	/**
	 * Schedule a command for execution
	 * 
	 * @param cmd the command to execute
	 * @return the pending command, which acts as a future for later completion
	 */
	//@Override
	@Override
	public <T> CompletableFuture<T> execute(DbgCommand<? extends T> cmd) {
		assert cmd != null;
		checkStarted();
		DbgPendingCommand<T> pcmd = new DbgPendingCommand<>(cmd);
		//if (isWaiting()) {
		//	throw new DebuggerModelAccessException(
		//		"Cannot process command " + cmd.toString() + " while engine is waiting for events");
		//}

		if (engThread.isCurrentThread()) {
			try {
				addCommand(cmd, pcmd);
			}
			catch (Throwable exc) {
				pcmd.completeExceptionally(exc);
			}
		}
		else {
			CompletableFuture.runAsync(() -> {
				addCommand(cmd, pcmd);
			}, engThread).exceptionally((exc) -> {
				pcmd.completeExceptionally(exc);
				return null;
			});
		}
		return pcmd;
	}

	private <T> void addCommand(DbgCommand<? extends T> cmd, DbgPendingCommand<T> pcmd) {
		synchronized (this) {
			if (!cmd.validInState(state.get())) {
				throw new LldbCommandError("Command " + cmd + " is not valid while " + state.get());
			}
			activeCmds.add(pcmd);
		}
		cmd.invoke();
		processEvent(new LldbCommandDoneEvent(cmd));
	}

	/*@Override
	public <T> DbgPendingCommand<T> execute1(DbgCommand<? extends T> cmd) {
		assert cmd != null;
		checkStarted();
		DbgPendingCommand<T> pcmd = new DbgPendingCommand<>(cmd);
		sequence(TypeSpec.VOID).then((seq) -> {
			Msg.debug(this, "WAITING cmdLock: " + pcmd);
			cmdLock.acquire(null).handle(seq::next);
		}, cmdLockHold).then((seq) -> {
			Msg.debug(this, "ACQUIRED cmdLock: " + pcmd);
			synchronized (this) {
				if (curCmd != null) {
					throw new AssertionError("Cannot execute more than one command at a time");
				}
				if (!cmd.validInState(state.get())) {
					throw new DbgCommandError(
						"Command " + cmd + " is not valid while " + state.get());
				}
				curCmd = pcmd;
			}
			cmd.invoke();
			processEvent(new DbgCommandDoneEvent(cmd.toString()));
			seq.exit();
		}).finish().exceptionally((exc) -> {
			pcmd.completeExceptionally(exc);
			Msg.debug(this, "ON_EXCEPTION: CURCMD = " + curCmd);
			curCmd = null;
			Msg.debug(this, "SET CURCMD = null");
			Msg.debug(this, "RELEASING cmdLock");
			cmdLockHold.getAndSet(null).release();
			return null;
		});
		return pcmd;
	}
	*/

	public DebugStatus processEvent(DbgEvent<?> evt) {
		if (state.get() == DbgState.STARTING) {
			state.set(DbgState.STOPPED, Causes.UNCLAIMED);
		}
		DbgState newState = evt.newState();
		if (newState != null && !(evt instanceof LldbCommandDoneEvent)) {
			Msg.debug(this, evt + " transitions state to " + newState);
			state.set(newState, evt.getCause());
		}

		boolean cmdFinished = false;
		List<DbgPendingCommand<?>> toRemove = new ArrayList<DbgPendingCommand<?>>();
		for (DbgPendingCommand<?> pcmd : activeCmds) {
			cmdFinished = pcmd.handle(evt);
			if (cmdFinished) {
				pcmd.finish();
				toRemove.add(pcmd);
			}
		}
		for (DbgPendingCommand<?> pcmd : toRemove) {
			activeCmds.remove(pcmd);
		}

		synchronized (this) {
			boolean waitState = isWaiting();
			waiting = false;
			DebugStatus ret = evt.isStolen() ? null : handlerMap.handle(evt, null);
			if (ret == null) {
				ret = DebugStatus.NO_CHANGE;
			}
			waiting = ret.equals(DebugStatus.NO_DEBUGGEE) ? false : waitState;
			return ret;
		}
	}

	@Override
	public void addStateListener(LldbStateListener listener) {
		state.addChangeListener(listener);
	}

	@Override
	public void removeStateListener(LldbEventsListener listener) {
		state.removeChangeListener(listener);
	}

	public ListenerSet<LldbEventsListener> getEventListeners() {
		return listenersEvent;
	}

	@Override
	public void addEventsListener(LldbEventsListener listener) {
		getEventListeners().add(listener);
	}

	@Override
	public void removeEventsListener(LldbEventsListener listener) {
		getEventListeners().remove(listener);
	}

	private DbgState stateFilter(StateType cur, StateType set, LldbCause cause) {
		if (set == null) {
			return cur;
		}
		return set;
	}

	private void trackRunningInterpreter(StateType oldSt, StateType st, LldbCause cause) {
		if (st == DbgState.RUNNING && cause instanceof DbgPendingCommand) {
			DbgPendingCommand<?> pcmd = (DbgPendingCommand<?>) cause;
			DbgCommand<?> command = pcmd.getCommand();
			Msg.debug(this, "Entered " + st + " from " + command);
		}
	}

	private void defaultHandlers() {
		handlerMap.put(LldbBreakpointEvent.class, this::processBreakpoint);
		handlerMap.put(LldbExceptionEvent.class, this::processException);
		handlerMap.put(SBThreadCreatedEvent.class, this::processThreadCreated);
		handlerMap.put(SBThreadExitedEvent.class, this::processThreadExited);
		handlerMap.put(SBThreadSelectedEvent.class, this::processThreadSelected);
		handlerMap.put(SBProcessCreatedEvent.class, this::processProcessCreated);
		handlerMap.put(SBProcessExitedEvent.class, this::processProcessExited);
		handlerMap.put(SBProcessSelectedEvent.class, this::processProcessSelected);
		handlerMap.put(LldbModuleLoadedEvent.class, this::processModuleLoaded);
		handlerMap.put(LldbModuleUnloadedEvent.class, this::processModuleUnloaded);
		handlerMap.put(LldbStateChangedEvent.class, this::processStateChanged);
		handlerMap.put(SBTargetSelectedEvent.class, this::processSessionSelected);
		handlerMap.put(LldbSystemsEvent.class, this::processSystemsEvent);
		handlerMap.putVoid(LldbCommandDoneEvent.class, this::processDefault);
		handlerMap.putVoid(LldbStoppedEvent.class, this::processDefault);
		handlerMap.putVoid(LldbRunningEvent.class, this::processDefault);
		handlerMap.putVoid(LldbConsoleOutputEvent.class, this::processConsoleOutput);
		handlerMap.putVoid(LldbBreakpointCreatedEvent.class, this::processBreakpointCreated);
		handlerMap.putVoid(LldbBreakpointModifiedEvent.class, this::processBreakpointModified);
		handlerMap.putVoid(LldbBreakpointDeletedEvent.class, this::processBreakpointDeleted);

		statusMap.put(LldbBreakpointEvent.class, DebugStatus.BREAK);
		statusMap.put(LldbExceptionEvent.class, DebugStatus.BREAK);
		statusMap.put(SBProcessCreatedEvent.class, DebugStatus.BREAK);
		statusMap.put(LldbStateChangedEvent.class, DebugStatus.NO_CHANGE);
		statusMap.put(LldbStoppedEvent.class, DebugStatus.BREAK);
	}

	private DebugThreadId updateState() {
		DebugClient dbgeng = engThread.getClient();
		DebugSystemObjects so = dbgeng.getSystemObjects();
		DebugThreadId etid = so.getEventThread();
		DebugProcessId epid = so.getEventProcess();
		DebugSessionId esid = so.getCurrentSystemId();

		DebugControl control = dbgeng.getControl();
		int execType = WinNTExtra.Machine.IMAGE_FILE_MACHINE_AMD64.val;
		try {
			so.setCurrentProcessId(epid);
			so.setCurrentThreadId(etid);
			execType = control.getExecutingProcessorType();
		}
		catch (Exception e) {
			// Ignore for now
		}

		lastEventInformation = control.getLastEventInformation();
		lastEventInformation.setSession(esid);
		lastEventInformation.setExecutingProcessorType(execType);
		currentSession = eventSession = getSessionComputeIfAbsent(esid);
		currentProcess =
			eventProcess = getProcessComputeIfAbsent(epid, so.getCurrentProcessSystemId());
		currentThread = eventThread = getThreadComputeIfAbsent(etid, (SBProcessImpl) eventProcess,
			so.getCurrentThreadSystemId());
		if (eventThread != null) {
			((SBThreadImpl) eventThread).setInfo(lastEventInformation);
		}
		return etid;
	}

	/**
	 * Default handler for events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected <T> DebugStatus processDefault(AbstractLldbEvent<T> evt, Void v) {
		//updateState();
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processBreakpoint(LldbBreakpointEvent evt, Void v) {
		updateState();

		DebugBreakpoint bp = evt.getInfo();
		LldbBreakpointInfo info = new LldbBreakpointInfo(bp, getEventProcess(), getEventThread());
		getEventListeners().fire.breakpointHit(info, evt.getCause());

		String key = Integer.toHexString(bp.getId());
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processException(LldbExceptionEvent evt, Void v) {
		DebugThreadId eventId = updateState();

		DebugExceptionRecord64 info = evt.getInfo();
		String key = Integer.toHexString(info.code);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadCreated(SBThreadCreatedEvent evt, Void v) {
		DebugClient dbgeng = engThread.getClient();
		DebugSystemObjects so = dbgeng.getSystemObjects();

		DebugThreadId eventId = updateState();
		SBProcessImpl process = getCurrentProcess();
		int tid = so.getCurrentThreadSystemId();
		SBThreadImpl thread = getThreadComputeIfAbsent(eventId, process, tid);
		getEventListeners().fire.threadCreated(thread, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());

		String key = Integer.toHexString(eventId.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadExited(SBThreadExitedEvent evt, Void v) {
		DebugThreadId eventId = updateState();
		SBProcessImpl process = getCurrentProcess();
		SBThreadImpl thread = getCurrentThread();
		if (thread != null) {
			thread.remove();
		}
		process.threadExited(eventId);
		getEventListeners().fire.threadExited(eventId, process, evt.getCause());

		String key = Integer.toHexString(eventId.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadSelected(SBThreadSelectedEvent evt, Void v) {
		DebugThreadId eventId = updateState();

		currentThread = evt.getThread();
		currentThread.setState(evt.getState(), evt.getCause(), evt.getReason());
		getEventListeners().fire.threadSelected(currentThread, evt.getFrame(), evt.getCause());

		String key = Integer.toHexString(eventId.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessCreated(SBProcessCreatedEvent evt, Void v) {
		DebugThreadId eventId = updateState();
		DebugClient dbgeng = engThread.getClient();
		DebugSystemObjects so = dbgeng.getSystemObjects();

		DebugProcessInfo info = evt.getInfo();
		long handle = info.handle;
		DebugProcessId id = so.getProcessIdByHandle(handle);
		so.setCurrentProcessId(id);
		int pid = so.getCurrentProcessSystemId();
		SBProcessImpl proc = getProcessComputeIfAbsent(id, pid);
		getEventListeners().fire.processAdded(proc, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.processSelected(proc, evt.getCause());

		handle = info.initialThreadInfo.handle;
		DebugThreadId idt = so.getThreadIdByHandle(handle);
		int tid = so.getCurrentThreadSystemId();
		SBThreadImpl thread = getThreadComputeIfAbsent(idt, proc, tid);
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());

		//proc.moduleLoaded(info.moduleInfo);
		//getEventListeners().fire.moduleLoaded(proc, info.moduleInfo, evt.getCause());

		String key = Integer.toHexString(id.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessExited(SBProcessExitedEvent evt, Void v) {
		DebugThreadId eventId = updateState();
		SBThreadImpl thread = getCurrentThread();
		SBProcessImpl process = getCurrentProcess();
		process.setExitCode(Long.valueOf(evt.getInfo()));
		getEventListeners().fire.threadExited(eventId, process, evt.getCause());

		getEventListeners().fire.processExited(process, evt.getCause());

		for (DebugBreakpoint bpt : getBreakpoints()) {
			breaksById.remove(bpt.getId());
		}
		if (thread != null) {
			thread.remove();
		}
		process.remove(evt.getCause());
		getEventListeners().fire.processRemoved(process.getId(), evt.getCause());

		String key = Integer.toHexString(process.getId().id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessSelected(SBProcessSelectedEvent evt, Void v) {
		DebugThreadId eventId = updateState();

		currentProcess = evt.getProcess();
		getEventListeners().fire.processSelected(currentProcess, evt.getCause());

		String key = Integer.toHexString(eventId.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module loaded events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processModuleLoaded(LldbModuleLoadedEvent evt, Void v) {
		updateState();
		SBProcessImpl process = getCurrentProcess();
		DebugModuleInfo info = evt.getInfo();
		process.moduleLoaded(info);
		getEventListeners().fire.moduleLoaded(process, info, evt.getCause());

		String key = info.getModuleName();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module unloaded events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processModuleUnloaded(LldbModuleUnloadedEvent evt, Void v) {
		updateState();
		SBProcessImpl process = getCurrentProcess();
		DebugModuleInfo info = evt.getInfo();
		process.moduleUnloaded(info);
		getEventListeners().fire.moduleUnloaded(process, info, evt.getCause());

		String key = info.getModuleName();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for state changed events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processStateChanged(LldbStateChangedEvent evt, Void v) {
		BitmaskSet<ChangeEngineState> flags = evt.getInfo();
		long argument = evt.getArgument();
		if (flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
			if (DebugStatus.isInsideWait(argument)) {
				return DebugStatus.NO_CHANGE;
			}
			status = DebugStatus.fromArgument(argument);

			if (status.equals(DebugStatus.NO_DEBUGGEE)) {
				waiting = false;
				return DebugStatus.NO_DEBUGGEE;
			}
			if (!threads.isEmpty()) {
				//SBTargetImpl session = getCurrentSession();
				//SBProcessImpl process = getCurrentProcess();
				eventThread = getCurrentThread();
				DbgState dbgState = null;
				if (eventThread != null) {
					if (status.threadState.equals(ExecutionState.STOPPED)) {
						dbgState = DbgState.STOPPED;
						//System.err.println("STOPPED " + id);
						processEvent(new LldbStoppedEvent(eventThread.getId()));
					}
					if (status.threadState.equals(ExecutionState.RUNNING)) {
						//System.err.println("RUNNING " + id);
						dbgState = DbgState.RUNNING;
						processEvent(new LldbRunningEvent(eventThread.getId()));
					}
					if (!threads.containsValue(eventThread)) {
						dbgState = DbgState.EXIT;
					}
					// Don't fire 
					if (dbgState != null && dbgState != DbgState.EXIT) {
						processEvent(new SBThreadSelectedEvent(dbgState, eventThread,
							evt.getFrame(eventThread)));
					}
					return DebugStatus.NO_CHANGE;
				}
			}
			if (status.equals(DebugStatus.BREAK)) {
				waiting = false;
				processEvent(new LldbStoppedEvent(getSystemObjects().getCurrentThreadId()));
				SBProcessImpl process = getCurrentProcess();
				if (process != null) {
					processEvent(new SBProcessSelectedEvent(process));
				}
				return DebugStatus.BREAK;
			}
			if (status.equals(DebugStatus.GO)) {
				waiting = true;
				processEvent(new LldbRunningEvent(getSystemObjects().getCurrentThreadId()));
				return DebugStatus.GO;
			}
			waiting = false;
			return DebugStatus.NO_CHANGE;
		}
		if (flags.contains(ChangeEngineState.BREAKPOINTS)) {
			long bptId = evt.getArgument();
			//System.err.println("BPT: " + bptId + ":" + flags + ":" + argument);
			processEvent(new LldbBreakpointModifiedEvent(bptId));
		}
		if (flags.contains(ChangeEngineState.CURRENT_THREAD)) {
			long id = evt.getArgument();
			for (DebugThreadId key : getThreads()) {
				if (key.id == id) {
					SBThread thread = getThread(key);
					if (thread != null) {
						getEventListeners().fire.threadSelected(thread, null, evt.getCause());
					}
					break;
				}
			}
		}
		if (flags.contains(ChangeEngineState.SYSTEMS)) {
			processEvent(new LldbSystemsEvent(argument));
		}
		return DebugStatus.NO_CHANGE;
	}

	/**
	 * Handler for session selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSessionSelected(SBTargetSelectedEvent evt, Void v) {
		DebugThreadId eventId = updateState();

		currentSession = evt.getSession();
		getEventListeners().fire.sessionSelected(currentSession, evt.getCause());

		String key = Integer.toHexString(eventId.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for systems events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSystemsEvent(LldbSystemsEvent evt, Void v) {

		waiting = true;

		Long info = evt.getInfo();
		DebugProcessId id = new DebugProcessId(info.intValue());

		String key = Integer.toHexString(id.id);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	protected void processConsoleOutput(LldbConsoleOutputEvent evt, Void v) {
		getEventListeners().fire.consoleOutput(evt.getInfo(), evt.getMask());
	}

	/**
	 * Handler for breakpoint-created event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointCreated(LldbBreakpointCreatedEvent evt, Void v) {
		doBreakpointCreated(evt.getBreakpointInfo(), evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointModified(LldbBreakpointModifiedEvent evt, Void v) {
		LldbBreakpointInfo breakpointInfo = evt.getBreakpointInfo();
		if (breakpointInfo == null) {
			long bptId = evt.getId();
			if (bptId == DbgEngUtil.DEBUG_ANY_ID.longValue()) {
				changeBreakpoints();
			}
			DebugBreakpoint bpt = getControl().getBreakpointById((int) bptId);
			if (bpt == null) {
				doBreakpointDeleted(bptId, evt.getCause());
				return;
			}
			LldbBreakpointInfo knownBreakpoint = getKnownBreakpoint(bptId);
			if (knownBreakpoint == null) {
				breakpointInfo = new LldbBreakpointInfo(bpt, getCurrentProcess());
				if (breakpointInfo.getOffset() != null) {
					doBreakpointCreated(breakpointInfo, evt.getCause());
				}
				return;
			}
			breakpointInfo = knownBreakpoint;
			breakpointInfo.setBreakpoint(bpt);

		}
		doBreakpointModified(breakpointInfo, evt.getCause());
	}

	/**
	 * Handler for breakpoint-deleted event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointDeleted(LldbBreakpointDeletedEvent evt, Void v) {
		doBreakpointDeleted(evt.getNumber(), evt.getCause());
	}

	/**
	 * Fire breakpoint created event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the creation
	 */
	@Internal
	public void doBreakpointCreated(LldbBreakpointInfo newInfo, LldbCause cause) {
		addKnownBreakpoint(newInfo, false);
		getEventListeners().fire.breakpointCreated(newInfo, cause);
	}

	/**
	 * Fire breakpoint modified event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the modification
	 */
	@Internal
	public void doBreakpointModified(LldbBreakpointInfo newInfo, LldbCause cause) {
		LldbBreakpointInfo oldInfo = addKnownBreakpoint(newInfo, true);
		getEventListeners().fire.breakpointModified(newInfo, oldInfo, cause);
	}

	/**
	 * Fire breakpoint deleted event
	 * 
	 * @param number the deleted breakpoint number
	 * @param cause the cause of the deletion
	 */
	@Internal
	public void doBreakpointDeleted(long number, LldbCause cause) {
		LldbBreakpointInfo oldInfo = removeKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		getEventListeners().fire.breakpointDeleted(oldInfo, cause);
	}

	protected void doBreakpointModifiedSameLocations(LldbBreakpointInfo newInfo,
			LldbBreakpointInfo oldInfo, LldbCause cause) {
		if (Objects.equals(newInfo, oldInfo)) {
			return;
		}
		getEventListeners().fire.breakpointModified(newInfo, oldInfo, cause);
	}

	@Internal
	public void doBreakpointDisabled(long number, LldbCause cause) {
		LldbBreakpointInfo oldInfo = getKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		LldbBreakpointInfo newInfo = oldInfo.withEnabled(false);
		doBreakpointModifiedSameLocations(newInfo, oldInfo, cause);
	}

	@Internal
	public void doBreakpointEnabled(long number, LldbCause cause) {
		LldbBreakpointInfo oldInfo = getKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		LldbBreakpointInfo newInfo = oldInfo.withEnabled(true);
		doBreakpointModifiedSameLocations(newInfo, oldInfo, cause);
	}

	private long orZero(Long l) {
		if (l == null) {
			return 0;
		}
		return l;
	}

	private void changeBreakpoints() {
		Set<Integer> retained = new HashSet<>();
		DebugSystemObjects so = getSystemObjects();
		try (SavedFocus focus = new SavedFocus(so)) {
			for (DebugProcessId pid : so.getProcesses()) {
				try {
					Msg.debug(this, "BREAKPOINTS: Changing current process to " + pid);
					so.setCurrentProcessId(pid);
				}
				catch (COMException e) {
					Msg.debug(this, e.getMessage());
					continue;
				}
				List<DebugThreadId> tids = so.getThreads();
				for (DebugBreakpoint bpt : getControl().getBreakpoints()) {
					BitmaskSet<BreakFlags> f = bpt.getFlags();
					if (!f.contains((BreakFlags.ENABLED)) || f.contains(BreakFlags.DEFERRED)) {
						continue;
					}
					if (bpt.getType().breakType != BreakType.CODE) {
						continue; // TODO: Extend SCTL to handle R/W breakpoints
					}
					int id = bpt.getId();
					retained.add(id);
					long newOffset = orZero(bpt.getOffset());
					BreakpointTag tag = breaksById.get(id);
					if (tag == null) {
						for (DebugThreadId tid : tids) {
							Msg.debug(this, "TRAP Added: " + id + " on " + tid);
							if (!claimsBreakpointAdded.satisfy(tid)) {
								/*
								AbstractSctlTrapSpec spec =
									server.getDialect().create(AbstractSctlTrapSpec.class);
								spec.setActionStop();
								spec.setAddress(newOffset);
								synth.synthSetTrap(null, tid.id, spec, id);
								*/
							}
							else {
								Msg.debug(this, "  claimed");
							}
							breaksById.put(id, new BreakpointTag(newOffset));
						}
					}
					else if (tag.offset != newOffset) {
						/*
						for (DebugThreadId tid : tids) {
							synth.synthClearTrap(null, tid.id, id);
							AbstractSctlTrapSpec spec =
								server.getDialect().create(AbstractSctlTrapSpec.class);
							spec.setActionStop();
							spec.setAddress(newOffset);
							synth.synthSetTrap(null, tid.id, spec, id);
						}
						*/
						tag.offset = newOffset;
					} // else the breakpoint is unchanged
				}
				Iterator<Integer> it = breaksById.keySet().iterator();
				while (it.hasNext()) {
					int id = it.next();
					if (retained.contains(id)) {
						continue;
					}
					for (DebugThreadId tid : tids) {
						Msg.debug(this, "TRAP Removed: " + id + " on " + tid);
						if (!claimsBreakpointRemoved.satisfy(new BreakId(tid, id))) {
							/*
							synth.synthClearTrap(null, tid.id, id);
							*/
						}
						else {
							Msg.debug(this, "  claimed");
						}
					}
					it.remove();
				}
			}
		}
		catch (COMException e) {
			Msg.error(this, "Error retrieving processes: " + e);
		}
	}

	@Override
	public CompletableFuture<Map<DebugProcessId, SBProcess>> listProcesses() {
		return execute(new LldbListProcessesCommand(this));
	}

	@Override
	public CompletableFuture<List<Pair<Integer, String>>> listAvailableProcesses() {
		return execute(new LldbListAvailableProcessesCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, SBTarget>> listSessions() {
		return CompletableFuture.completedFuture(null);
		///return execute(new DbgListSessionsCommand(this));
	}

	@Override
	public void sendInterruptNow() {
		checkStarted();
		Msg.info(this, "Interrupting");
		// NB: don't use "execute" here - engThread is paused on waitForEvents
		//  and execute::sequence blocks on engThread 
		reentrantClient.getControl().setInterrupt(DebugInterrupt.ACTIVE);
	}

	@Override
	public CompletableFuture<SBProcess> addProcess() {
		return execute(new LldbAddProcessCommand(this));
	}

	@Override
	public CompletableFuture<Void> removeProcess(SBProcess process) {
		return execute(new LldbRemoveProcessCommand(this, process.getId()));
	}

	@Override
	public CompletableFuture<SBTarget> addSession() {
		return execute(new LldbAddSessionCommand(this));
	}

	@Override
	public CompletableFuture<Void> removeSession(SBTarget session) {
		return execute(new LldbRemoveSessionCommand(this, session.getId()));
	}

	@Override
	public CompletableFuture<?> launch(List<String> args) {
		return execute(new LldbLaunchProcessCommand(this, args));
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		return CompletableFuture.completedFuture(null);
	}

	public CompletableFuture<?> openFile(Map<String, ?> args) {
		return execute(new LldbOpenDumpCommand(this, args));
	}

	public CompletableFuture<?> attachKernel(Map<String, ?> args) {
		setKernelMode(true);
		return execute(new LldbAttachKernelCommand(this, args));
	}

	static class ExitEvent {
		final DebugThreadId tid;
		final long exitCode;

		public ExitEvent(DebugThreadId tid, long exitCode) {
			this.tid = tid;
			this.exitCode = exitCode;
		}
	}

	static class BreakId {
		final DebugThreadId tid;
		final int bpid;

		public BreakId(DebugThreadId tid, int bpid) {
			this.tid = tid;
			this.bpid = bpid;
		}
	}

	static class BreakpointTag {
		long offset;

		public BreakpointTag(long offset) {
			this.offset = offset;
		}
	}

	class SavedFocus implements AutoCloseable {
		final DebugSystemObjects so;
		DebugThreadId tid = null;

		public SavedFocus(DebugSystemObjects so) {
			this.so = so;
			try {
				tid = so.getCurrentThreadId();
			}
			catch (COMException e) {
				Msg.debug(this, "Cannot save current thread id: " + e);
			}
		}

		@Override
		public void close() {
			if (tid != null) {
				try {
					so.setCurrentThreadId(tid);
				}
				catch (COMException e) {
					Msg.debug(this, "Could not restore current thread id: " + e);
				}
			}
		}
	}

	public DebugClient getClient() {
		return engThread.getClient();
	}

	public DebugAdvanced getAdvanced() {
		DebugClient dbgeng = getClient();
		return dbgeng.getAdvanced();
	}

	public DebugControl getControl() {
		DebugClient dbgeng = getClient();
		return dbgeng.getControl();
	}

	public DebugDataSpaces getDataSpaces() {
		DebugClient dbgeng = getClient();
		return dbgeng.getDataSpaces();
	}

	public DebugRegisters getRegisters() {
		DebugClient dbgeng = getClient();
		return dbgeng.getRegisters();
	}

	public DebugSymbols getSymbols() {
		DebugClient dbgeng = getClient();
		return dbgeng.getSymbols();
	}

	public DebugSystemObjects getSystemObjects() {
		DebugClient dbgeng = getClient();
		return dbgeng.getSystemObjects();
	}

	public List<DebugThreadId> getThreads() {
		DebugSystemObjects so = getSystemObjects();
		return so.getThreads();
	}

	private List<DebugBreakpoint> getBreakpoints() {
		DebugControl control = getControl();
		return control.getBreakpoints();
	}

	public SBThread getCurrentThread() {
		return currentThread != null ? currentThread : eventThread;
	}

	public void setCurrentThread(SBThread thread) {
		currentThread = thread;
	}

	public SBProcess getCurrentProcess() {
		return currentProcess != null ? currentProcess : eventProcess;
	}

	public SBTarget getCurrentSession() {
		return currentSession != null ? currentSession : eventSession;
	}

	public SBThread getEventThread() {
		return eventThread;
	}

	public SBProcess getEventProcess() {
		return eventProcess;
	}

	public SBTarget getEventSession() {
		return eventSession;
	}

	public CompletableFuture<Void> setActiveFrame(SBThread thread, int index) {
		currentThread = thread;
		return execute(new LldbSetActiveThreadCommand(this, thread, index));
	}

	public CompletableFuture<Void> setActiveThread(SBThread thread) {
		currentThread = thread;
		return execute(new LldbSetActiveThreadCommand(this, thread, null));
	}

	public CompletableFuture<Void> setActiveProcess(SBProcess process) {
		currentProcess = process;
		return execute(new LldbSetActiveProcessCommand(this, process));
	}

	public CompletableFuture<Void> setActiveSession(SBTarget session) {
		currentSession = session;
		return execute(new LldbSetActiveSessionCommand(this, session));
	}

	public CompletableFuture<Void> requestFocus(DbgModelTargetFocusScope scope, TargetObject obj) {
		return execute(new LldbRequestFocusCommand(this, scope, obj));
	}

	public CompletableFuture<Void> requestActivation(DbgModelTargetActiveScope activator,
			TargetObject obj) {
		return execute(new LldbRequestActivationCommand(this, activator, obj));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		if (continuation != null) {
			String prompt = command.equals("") ? DbgModelTargetInterpreter.DBG_PROMPT : ">>>";
			getEventListeners().fire.promptChanged(prompt);
			continuation.complete(command);
			setContinuation(null);
			return AsyncUtils.NIL;
		}
		return execute(
			new LldbConsoleExecCommand(this, command, LldbConsoleExecCommand.Output.CONSOLE))
					.thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return execute(
			new LldbConsoleExecCommand(this, command, LldbConsoleExecCommand.Output.CAPTURE));
	}

	public void fireThreadExited(DebugThreadId id, SBProcessImpl process, LldbCause cause) {
		getEventListeners().fire.threadExited(id, process, cause);
	}

	@Override
	public DbgState getState() {
		return state.get();
	}

	@Override
	public SBProcess currentProcess() {
		return getCurrentProcess();
	}

	@Override
	public CompletableFuture<Void> waitForEventEx() {
		//System.err.println("ENTER");
		DebugControl control = getControl();
		waiting = true;
		control.waitForEvent();
		//System.err.println("EXIT");
		waiting = false;
		updateState();
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> waitForState(DbgState forState) {
		checkStarted();
		return state.waitValue(forState);
	}

	@Override
	public CompletableFuture<Void> waitForPrompt() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public DebugEventInformation getLastEventInformation() {
		return lastEventInformation;
	}

	public CompletableFuture<? extends Map<String, ?>> getRegisterMap(List<String> path) {
		return null;
	}

	public boolean isWaiting() {
		return waiting;
	}

	public boolean isKernelMode() {
		return kernelMode;
	}

	public void setKernelMode(boolean kernelMode) {
		this.kernelMode = kernelMode;
	}

	public void setContinuation(CompletableFuture<String> continuation) {
		this.continuation = continuation;
	}
}
