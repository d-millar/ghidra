package agent.lldb.lldb;

import static org.junit.Assume.*;

import java.math.BigInteger;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.evt.*;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

public class DebugClientImpl implements DebugClient {

	private LldbManager manager;
	private SBDebugger sbd;
	private SBTarget session;
	private SBEvent event;
	private DebugOutputCallbacks ocb;
	private DebugEventCallbacks ecb;
	private SBCommandInterpreter cmd;

	public DebugClientImpl() {
	}

	@Override
	public DebugClient createClient() {
		try {
			//TODO: fix this
			System.load("/Users/llero/git/llvm-build/lib/liblldb.dylib");
		}
		catch (UnsatisfiedLinkError ex) {
			assumeTrue("liblldb.dylib not found. Probably not OSX here.", false);
		}
		SBDebugger.InitializeWithErrorHandling();
		event = new SBEvent();
		sbd = SBDebugger.Create();
		cmd = sbd.GetCommandInterpreter();
		return this;
	}
	
	public SBDebugger getDebugger() {
		return sbd;
	}
	
	@Override
	public SBListener getListener() {
		return sbd.GetListener();
	}

	@Override
	public void endSessionReentrant() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public DebugServerId getLocalServer() {
		return new DebugServerId(0);
	}

	@Override
	public void attachKernel(long flags, String options) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void startProcessServer(String options) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public DebugServerId connectProcessServer(String options) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean dispatchCallbacks(int timeout) {
		return false;
	}

	@Override
	public void flushCallbacks() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void exitDispatch(DebugClient client) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void attach(DebugServerId si, SBAttachInfo info) {
		SBError error = new SBError();
		session.Attach(info, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " for attach");
		}
	}

	@Override
	public void attachProcess(DebugServerId si, String processName, boolean wait, BitmaskSet<DebugAttachFlags> attachFlags) {
		SBListener listener = new SBListener();
		SBError error = new SBError();
		session.AttachToProcessWithName(listener, processName, wait, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while attaching to " + processName);
		}
	}

	@Override
	public void attachProcess(DebugServerId si, BigInteger processId, BitmaskSet<DebugAttachFlags> attachFlags) {
		SBListener listener = new SBListener();
		SBError error = new SBError();
		session.AttachToProcessWithID(listener, processId, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while attaching to " + processId);
		}
	}

	@Override
	public void createProcess(DebugServerId si, SBLaunchInfo info) {
		SBError error = new SBError();
		String cmd = info.GetExecutableFile().GetDirectory();
		cmd += "/"+info.GetExecutableFile().GetFilename();
		for (int i = 0; i < info.GetNumArguments(); i++) {
			cmd += " "+info.GetArgumentAtIndex(i);
		}
		session = connectSession(cmd);
		SBProcess process = session.Launch(info, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " for create process");
		}
	}
	
	@Override
	public void createProcess(DebugServerId si, String commandLine, BitmaskSet<DebugCreateFlags> createFlags) {
		//TODO: fix this
		session = connectSession(commandLine);
		//session = connectSession("/opt/X11/bin/xclock-x86_64");
		SBListener listener = new SBListener();
		SBError error = new SBError();
		SBProcess process = session.Launch(listener, null, null, "", "", "", "", 0, true, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while launching " + commandLine);
		}
		//SBProcess process = session.LaunchSimple(null, null, null);
		/*
		listener = new SBListener(process.GetProcessID().toString());
		broadcaster = process.GetBroadcaster();
		broadcaster.AddListener(listener, SBProcess.eBroadcastBitStateChanged);
		event = new SBEvent();
		executor = new LldbClientThreadExecutor(() -> createClient());
		*/
	}

	@Override
	public void startServer(String options) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void waitForProcessServerEnd(int timeout) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void terminateCurrentProcess() {
		session.GetProcess().Destroy();
	}

	@Override
	public void detachCurrentProcess() {
		session.GetProcess().Detach();
	}

	@Override
	public SBTarget connectSession(String commandLine) {
		return sbd.CreateTarget(commandLine);
	}

	@Override
	public void endSession(DebugEndSessionFlags flags) {
		sbd.DeleteTarget(session);
	}

	@Override
	public void openDumpFileWide(String fileName) {
		SBError error = new SBError();
		session.LoadCore(fileName, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while loading " + fileName);
		}
	}

	@Override
	public SBEvent waitForEvent() {
		boolean eventFound = getListener().WaitForEvent(-1, event);
		if (eventFound) {
			return event;
		}
		return null;
	}

	public void translateAndFireEvent(SBEvent evt) {
		manager.setCurrentEvent(evt);
		long type = evt.GetType();
		if (SBTarget.EventIsTargetEvent(evt)) {
			if ((type & SBTarget.eBroadcastBitBreakpointChanged) != 0) {
				Msg.info(this, "*** Breakpoint Changed: " + evt.GetType());
				processEvent(new LldbBreakpointModifiedEvent(new DebugBreakpointInfo(evt)));
			}
			if ((type & SBTarget.eBroadcastBitModulesLoaded) != 0) {
				Msg.info(this, "*** Module Loaded: " + evt.GetType());
				processEvent(new LldbModuleLoadedEvent(new DebugModuleInfo(evt)));
			}
			if ((type & SBTarget.eBroadcastBitModulesUnloaded) != 0) {
				Msg.info(this, "*** Module Unloaded: " + evt.GetType());
				processEvent(new LldbModuleUnloadedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitWatchpointChanged) != 0) {
				Msg.info(this, "*** Watchpoint Changed: " + evt.GetType());
				//fireEvent(new LldbWatchpointModifiedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitSymbolsLoaded) != 0) {
				Msg.info(this, "*** Symbols Loaded: " + evt.GetType());
				//fireEvent(new LldbSymbolsLoadedEvent(null));
			}
		}
		
		if (SBProcess.EventIsProcessEvent(evt)) {
			if ((type & SBProcess.eBroadcastBitStateChanged) != 0) {
				Msg.info(this, "*** State Changed: " + evt.GetType());
				processEvent(new LldbStateChangedEvent(new DebugEventInfo(evt)));
			}
			if ((type & SBProcess.eBroadcastBitInterrupt) != 0) {
				Msg.info(this, "*** Interrupt: " + evt.GetType());
				//fireEvent(new LldbInterrupt(null));
			}
			if ((type & SBProcess.eBroadcastBitSTDOUT) != 0) {
				Msg.info(this, "*** Console STDOU: " + evt.GetType());
				processEvent(new LldbConsoleOutputEvent(0, null));
			}
			if ((type & SBProcess.eBroadcastBitSTDERR) != 0) {
				Msg.info(this, "*** Console STDERR: " + evt.GetType());
				processEvent(new LldbConsoleOutputEvent(0, null));
			}
			if ((type & SBProcess.eBroadcastBitProfileData) != 0) {
				Msg.info(this, "*** Profile Data Added: " + evt.GetType());
				//fireEvent(new LldbProfileDataEvent(null));
			}
			if ((type & SBProcess.eBroadcastBitStructuredData) != 0) {
				Msg.info(this, "*** Structured Data Added: " + evt.GetType());
				//fireEvent(new LldbStructuredDataEvent(null));
			}
		}
		
		if (SBThread.EventIsThreadEvent(evt)) {
			if ((type & SBThread.eBroadcastBitStackChanged) != 0) {
				Msg.info(this, "*** Stack Changed: " + evt.GetType());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadSuspended) != 0) {
				Msg.info(this, "*** Thread Suspended: " + evt.GetType());
				//fireEvent(new LldbThreadSuspendedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadResumed) != 0) {
				Msg.info(this, "*** Thread Resumed: " + evt.GetType());
				//fireEvent(new LldbThreadResumedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitSelectedFrameChanged) != 0) {
				Msg.info(this, "*** Frame Selected: " + evt.GetType());
				//fireEvent(new LldbSelectedFrameChangedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadSelected) != 0) {
				Msg.info(this, "*** Thread Selected: " + evt.GetType());
				processEvent(new LldbThreadSelectedEvent(null, null, null));
			}
		}
		if (SBBreakpoint.EventIsBreakpointEvent(evt)) {
			BreakpointEventType btype = SBBreakpoint.GetBreakpointEventTypeFromEvent(evt);
			SBBreakpoint bpt = SBBreakpoint.GetBreakpointFromEvent(evt);
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeAdded)) {
				Msg.info(this, "*** Breakpoint Added: " + bpt.GetID());
				processEvent(new LldbBreakpointCreatedEvent(new DebugBreakpointInfo(bpt)));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeAutoContinueChanged)) {
				Msg.info(this, "*** Breakpoint Auto Continue: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeCommandChanged)) {
				Msg.info(this, "*** Breakpoint Command Changed: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeConditionChanged)) {
				Msg.info(this, "*** Breakpoint Condition Changed: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeDisabled)) {
				Msg.info(this, "*** Breakpoint Disabled: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeEnabled)) {
				Msg.info(this, "*** Breakpoint Enabled: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeIgnoreChanged)) {
				Msg.info(this, "*** Breakpoint Ignore Changed: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeInvalidType)) {
				Msg.info(this, "*** Breakpoint Invalid Type: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeLocationsAdded)) {
				Msg.info(this, "*** Breakpoint Locations Added: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeLocationsRemoved)) {
				Msg.info(this, "*** Breakpoint Locations Removed: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeLocationsResolved)) {
				Msg.info(this, "*** Breakpoint Locations Resolved: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeRemoved)) {
				Msg.info(this, "*** Breakpoint Removed: " + bpt.GetID());
				processEvent(new LldbBreakpointDeletedEvent(new DebugBreakpointInfo(bpt)));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeThreadChanged)) {
				Msg.info(this, "*** Breakpoint Thread Changed: " + bpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}		
		}
		if (SBWatchpoint.EventIsWatchpointEvent(evt)) {
			WatchpointEventType wtype = SBWatchpoint.GetWatchpointEventTypeFromEvent(evt);
			SBWatchpoint wpt = SBWatchpoint.GetWatchpointFromEvent(evt);
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeAdded)) {
				Msg.info(this, "*** Watchpoint Added: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeCommandChanged)) {
				Msg.info(this, "*** Watchpoint Command Changed: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeConditionChanged)) {
				Msg.info(this, "*** Watchpoint Condition Changed: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeDisabled)) {
				Msg.info(this, "*** Watchpoint Disabled: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeEnabled)) {
				Msg.info(this, "*** Watchpoint Enabled: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeIgnoreChanged)) {
				Msg.info(this, "*** Watchpoint Ignore Changed: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeInvalidType)) {
				Msg.info(this, "*** Watchpoint Invalid Type: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeRemoved)) {
				Msg.info(this, "*** Watchpoint Removed: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeThreadChanged)) {
				Msg.info(this, "*** Watchpoint Thread Changed: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeTypeChanged)) {
				Msg.info(this, "*** Watchpoint Type Changed: " + wpt.GetID());
				//fireEvent(new LldbStackChangedEvent(null));
			}		
		}
	}

	public void processEvent(LldbEvent<?> lldbEvt) {
		manager.processEvent(lldbEvt);
	}

	@Override
	public DebugStatus getExecutionStatus() {
		StateType state = manager.getState();
		return DebugStatus.fromArgument(state);
	}

	@Override
	public void setOutputCallbacks(DebugOutputCallbacks cb) {
		this.ocb = cb;
	}

	@Override
	public void setEventCallbacks(DebugEventCallbacks cb) {
		this.ecb = cb;
	}

	@Override
	public boolean getInterrupt() {
		return false;
	}

	@Override
	public void setManager(LldbManager manager) {
		this.manager = manager;
	}

	@Override
	public void addBroadcaster(Object object) {
		if (object instanceof SBCommandInterpreter) {
			SBCommandInterpreter interpreter = (SBCommandInterpreter) object;
			interpreter.GetBroadcaster().AddListener(getListener(), ChangeSessionState.SESSION_ALL.getMask());
		}
		if (object instanceof SBTarget) {
			SBTarget session = (SBTarget) object;
			session.GetBroadcaster().AddListener(getListener(), ChangeSessionState.SESSION_ALL.getMask());
		}
		if (object instanceof SBProcess) {
			SBProcess process = (SBProcess) object;
			process.GetBroadcaster().AddListener(getListener(), ChangeProcessState.PROCESS_ALL.getMask());
		}
	}

	@Override
	public void execute(String command) {
		SBCommandReturnObject res = new SBCommandReturnObject();
		cmd.HandleCommand(command, res);
		if (res.GetErrorSize() > 0) {
			ocb.output(DebugOutputFlags.DEBUG_OUTPUT_ERROR.ordinal(), res.GetError());
		}
		if (res.GetOutputSize() > 0) {
			ocb.output(DebugOutputFlags.DEBUG_OUTPUT_NORMAL.ordinal(), res.GetOutput());
		}
	}

}
