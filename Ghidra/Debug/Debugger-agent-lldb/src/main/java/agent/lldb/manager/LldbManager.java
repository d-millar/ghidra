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
package agent.lldb.manager;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.Pair;

import SWIG.SBBreakpoint;
import SWIG.SBBreakpointLocation;
import SWIG.SBEvent;
import SWIG.SBFrame;
import SWIG.SBMemoryRegionInfo;
import SWIG.SBModule;
import SWIG.SBProcess;
import SWIG.SBSection;
import SWIG.SBSymbol;
import SWIG.SBTarget;
import SWIG.SBThread;
import SWIG.SBValue;
import SWIG.StateType;
import agent.lldb.lldb.DebugClient.DebugStatus;
import agent.lldb.manager.LldbManager.ExecSuffix;
import agent.lldb.manager.breakpoint.LldbBreakpointInsertions;
import agent.lldb.manager.impl.LldbManagerImpl;

public interface LldbManager extends AutoCloseable, LldbBreakpointInsertions {

	/**
	 * Possible values for {@link DbgThread#step(ExecSuffix)}
	 */
	public enum ExecSuffix {
		/** Equivalent to {@code finish} in the CLI */
		FINISH("finish"),
		/** Equivalent to {@code next} in the CLI */
		NEXT("next"),
		/** Equivalent to {@code nexti} in the CLI */
		NEXT_INSTRUCTION("next-instruction"),
		/** Equivalent to {@code return} in the CLI */
		RETURN("return"),
		/** Equivalent to {@code step} in the CLI */
		STEP("step"),
		/** Equivalent to {@code stepi} in the CLI */
		STEP_INSTRUCTION("step-instruction"),
		/** Equivalent to {@code until} in the CLI */
		UNTIL("until"),
		/** Equivalent to {@code ext} in the CLI */
		EXTENDED("ext"),;

		final String str;

		ExecSuffix(String str) {
			this.str = str;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	static LldbManager newInstance() {
		return new LldbManagerImpl();
	}

	/**
	 * Launch dbgeng
	 * 
	 * @param args cmd plus args
	 * @return a future which completes when dbgeng is ready to accept commands
	 */
	CompletableFuture<Void> start(String[] args);

	/**
	 * Terminate dbgeng
	 */
	void terminate();

	/**
	 * Check if GDB is alive
	 * 
	 * Note this is not about the state of inferiors in GDB. If the GDB controlling process is
	 * alive, GDB is alive.
	 * 
	 * @return true if GDB is alive, false otherwise
	 */
	boolean isRunning();

	/**
	 * Add a listener for dbgeng's state
	 * 
	 * @see #getState()
	 * @param listener the listener to add
	 */
	void addStateListener(LldbStateListener listener);

	/**
	 * Remove a listener for dbgeng's state
	 * 
	 * @see #getState()
	 * @param listener the listener to remove
	 */
	void removeStateListener(LldbStateListener listener);

	/**
	 * Add a listener for events on processes
	 * 
	 * @param listener the listener to add
	 */
	void addEventsListener(LldbEventsListener listener);

	/**
	 * Remove a listener for events on inferiors
	 * 
	 * @param listener the listener to remove
	 */
	void removeEventsListener(LldbEventsListener listener);

	/**
	 * Get a thread by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers its threads using a global counter. These IDs are unrelated to the OS-assigned
	 * TID. This method can retrieve a thread by its ID no matter which inferior it belongs to.
	 * 
	 * @param id the dbgeng-asigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	SBThread getThread(SBProcess process, String id);

	/**
	 * Get an process by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addProcess()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	SBProcess getProcess(SBTarget session, String id);

	/**
	 * Get an session by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	SBTarget getSession(String id);

	/**
	 * Get an session by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	SBModule getModule(SBTarget session, String id);

	/**
	 * Get all threads known to the manager
	 * 
	 * This does not ask dbgeng to lists its known threads. Rather it returns a read-only view of
	 * the manager's understanding of the current threads based on its tracking of dbgeng events.
	 * 
	 * @return a map of dbgeng-assigned thread IDs to corresponding thread handles
	 */
	Map<String, SBThread> getKnownThreads(SBProcess process);

	/**
	 * Get all processes known to the manager
	 * 
	 * This does not ask dbgeng to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current processes based on its tracking of dbgeng events.
	 * 
	 * @return a map of process IDs to corresponding process handles
	 */
	Map<String, SBProcess> getKnownProcesses(SBTarget session);

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask dbgeng to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of dbgeng events.
	 * 
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, SBTarget> getKnownSessions();

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask dbgeng to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of dbgeng events.
	 * 
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, SBModule> getKnownModules(SBTarget session);

	/**
	 * Get all breakpoints known to the manager
	 * 
	 * This does not ask dbgeng to list its breakpoints. Rather it returns a read-only view of the
	 * manager's understanding of the current breakpoints based on its tracking of dbgeng events.
	 * 
	 * @return a map of dbgeng-assigned breakpoint IDs to corresponding breakpoint information
	 */
	Map<String, SBBreakpoint> getKnownBreakpoints(SBTarget session);

	/**
	 * Send an interrupt to dbgeng regardless of other queued commands
	 * 
	 * This may be useful if the manager's command queue is stalled because an inferior is running.
	 * 
	 */
	void sendInterruptNow();

	/**
	 * Get the state of the dbgeng session
	 * 
	 * In all-stop mode, if any thread is running, dbgeng is said to be in the running state and is
	 * unable to process commands. Otherwise, if all threads are stopped, then dbgeng is said to be
	 * in the stopped state and can accept and process commands. This manager has not been tested in
	 * non-stop mode.
	 * 
	 * @return the state
	 */
	StateType getState();

	/**
	 * Add a process
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<SBProcess> addProcess();

	/**
	 * Remove a process
	 * 
	 * @param process the process to remove
	 * @return a future which completes then dbgeng has executed the command
	 */
	CompletableFuture<Void> removeProcess(SBProcess process);

	/**
	 * Add a session
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<SBTarget> addSession();

	/**
	 * Remove a session
	 * 
	 * @param process the session to remove
	 * @return a future which completes then dbgeng has executed the command
	 */
	CompletableFuture<Void> removeSession(SBTarget session);

	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * Note: to ensure a certain thread or inferior has focus for a console command, see
	 * {@link DbgThread#console(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> console(String command);

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * The output will not be printed to the CLI console. To ensure a certain thread or inferior has
	 * focus for a console command, see {@link DbgThread#consoleCapture(String)} and
	 * {@link DbgProcess#consoleCapture(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when dbgeng has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

	/**
	 * List dbgeng's threads
	 * 
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Map<String, SBThread>> listThreads(SBProcess process);

	/**
	 * List dbgeng's processes
	 * 
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Map<String, SBProcess>> listProcesses(SBTarget session);

	/**
	 * List the available processes on target
	 * 
	 * @return a future that completes with a list of PIDs
	 */
	CompletableFuture<List<Pair<String, String>>> listAvailableProcesses();

	/**
	 * List dbgeng's sessions
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBTarget>> listSessions();

	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBFrame>> listStackFrames(SBThread thread);

	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBValue>> listStackFrameRegisterBanks(SBFrame frame);

	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBValue>> listStackFrameRegisters(SBValue bank);

	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, SBModule>> listModules(SBTarget session);
	
	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, SBSection>> listModuleSections(SBModule module);
	
	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, SBSymbol>> listModuleSymbols(SBModule module);
		
	/**
	 * List dbgeng's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<List<SBMemoryRegionInfo>> listMemory(SBProcess process);
	
	/**
	 * List information for all breakpoints
	 * 
	 * @return a future that completes with a list of information for all breakpoints
	 */
	CompletableFuture<Map<String, SBBreakpoint>> listBreakpoints(SBTarget session);
	/**
	 * List information for all breakpoints
	 * 
	 * @return a future that completes with a list of information for all breakpoints
	 */
	CompletableFuture<Map<String, SBBreakpointLocation>> listBreakpointLocations(SBBreakpoint spec);

	/**
	 * Disable the given breakpoints
	 * 
	 * This is equivalent to the CLI command {@code disable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the dbgeng-assigned breakpoint numbers
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> disableBreakpoints(long... numbers);

	/**
	 * Enable the given breakpoints
	 * 
	 * This is equivalent to the CLI command {@code enable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the dbgeng-assigned breakpoint numbers
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> enableBreakpoints(long... numbers);

	/**
	 * Delete a breakpoint
	 * 
	 * This is equivalent to the CLI command {@code delete breakpoint [NUMBER]}.
	 * 
	 * @param numbers the dbgeng-assigned breakpoint numbers
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> deleteBreakpoints(long... numbers);

	CompletableFuture<?> launch(List<String> args);

	CompletableFuture<Void> launch(Map<String, ?> args);

	/********** NEEDED FOR TESTING ************/

	/**
	 * Returns the current process
	 * 
	 * @return the current process
	 */
	SBProcess currentProcess();

	CompletableFuture<Void> waitForState(StateType stopped);

	CompletableFuture<Void> waitForPrompt();

	CompletableFuture<Void> waitForEventEx();

	<T> CompletableFuture<T> execute(LldbCommand<? extends T> cmd);

	DebugStatus processEvent(LldbEvent<?> evt);

	//DebugEventInformation getLastEventInformation();

	DebugStatus getStatus();

	void setCurrentEvent(SBEvent evt);

}
