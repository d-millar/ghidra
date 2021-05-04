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

import java.nio.file.Paths;

import agent.lldb.lldb.DebugBreakpoint;
import agent.lldb.lldb.DebugClient.DebugStatus;
import agent.lldb.lldb.DebugModuleInfo;
import agent.lldb.lldb.DebugProcessInfo;
import agent.lldb.lldb.DebugSessionInfo;
import agent.lldb.lldb.DebugThreadInfo;
import agent.lldb.lldb.util.DebugEventCallbacksAdapter;
import agent.lldb.manager.evt.LldbBreakpointEvent;
import agent.lldb.manager.evt.LldbModuleLoadedEvent;
import agent.lldb.manager.evt.LldbModuleUnloadedEvent;
import agent.lldb.manager.evt.LldbProcessCreatedEvent;
import agent.lldb.manager.evt.LldbProcessExitedEvent;
import agent.lldb.manager.evt.LldbSessionCreatedEvent;
import agent.lldb.manager.evt.LldbSessionExitedEvent;
import agent.lldb.manager.evt.LldbThreadCreatedEvent;
import agent.lldb.manager.evt.LldbThreadExitedEvent;
import ghidra.util.Msg;

public class LldbDebugEventCallbacksAdapter extends DebugEventCallbacksAdapter {
	private LldbManagerImpl manager;

	public LldbDebugEventCallbacksAdapter(LldbManagerImpl manager) {
		super();
		this.manager = manager;
	}

	protected DebugStatus checkInterrupt(DebugStatus normal) {
		if (manager.getClient().getInterrupt()) {
			return DebugStatus.BREAK;
		}
		return normal;
	}

	@Override
	public DebugStatus breakpoint(DebugBreakpoint bp) {
		Msg.info(this, "***Breakpoint: " + bp.getId());
		return checkInterrupt(manager.processEvent(new LldbBreakpointEvent(bp)));
	}

	@Override
	public DebugStatus createThread(DebugThreadInfo threadInfo) {
		Msg.info(this, "***Thread created: " + Integer.toHexString(threadInfo.id));
		return checkInterrupt(manager.processEvent(new LldbThreadCreatedEvent(threadInfo)));
	}

	@Override
	public DebugStatus exitThread(int exitCode) {
		Msg.info(this, "***Thread exited: " + exitCode);
		return checkInterrupt(manager.processEvent(new LldbThreadExitedEvent(exitCode)));
	}

	@Override
	public DebugStatus createProcess(DebugProcessInfo processInfo) {
		Msg.info(this, "***Process created: " + Integer.toHexString(processInfo.id));
		return checkInterrupt(manager.processEvent(new LldbProcessCreatedEvent(processInfo)));
	}

	@Override
	public DebugStatus exitProcess(int exitCode) {
		Msg.info(this, "***Process exited: " + exitCode);
		return checkInterrupt(manager.processEvent(new LldbProcessExitedEvent(exitCode)));
	}

	@Override
	public DebugStatus createSession(DebugSessionInfo sessionInfo) {
		Msg.info(this, "***Session created: " + Integer.toHexString(sessionInfo.id));
		return checkInterrupt(manager.processEvent(new LldbSessionCreatedEvent(sessionInfo)));
	}

	@Override
	public DebugStatus exitSession(int exitCode) {
		Msg.info(this, "***Session exited: " + exitCode);
		return null; //checkInterrupt(manager.processEvent(new LldbSessionExitedEvent(exitCode)));
	}

	@Override
	public DebugStatus loadModule(DebugModuleInfo moduleInfo) {
		Msg.info(this, "***Module Loaded: " + moduleInfo);
		return checkInterrupt(manager.processEvent(new LldbModuleLoadedEvent(moduleInfo)));
	}

	@Override
	public DebugStatus unloadModule(String imageBaseName, long baseOffset) {
		Msg.info(this,
			"***Module Unloaded: " + imageBaseName + ", " + Long.toHexString(baseOffset));
		//DebugModuleInfo info =
		//	new DebugModuleInfo(0L, baseOffset, 0, basename(imageBaseName), imageBaseName, 0, 0);
		return null; //checkInterrupt(manager.processEvent(new LldbModuleUnloadedEvent(info)));
	}

	private String basename(String path) {
		return Paths.get(path).getFileName().toString();
	}

	/*
	@Override
	public DebugStatus changeEngineState(BitmaskSet<ChangeEngineState> flags, long argument) {
		LldbStateChangedEvent event = new LldbStateChangedEvent(null);
		event.setArgument(argument);
		if (flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
			if (DebugStatus.isInsideWait(argument)) {
				return DebugStatus.NO_CHANGE;
			}
			DebugStatus status = DebugStatus.fromArgument(argument);
			Msg.info(this, "***ExecutionStatus: " + status);
			if (status.equals(DebugStatus.NO_DEBUGGEE)) {
				event.setState(StateType.eStateExited);
			}
			return checkInterrupt(manager.processEvent(event));
		}
		if (flags.contains(ChangeEngineState.BREAKPOINTS)) {
			Msg.info(this, "***BreakpointChanged: " + flags + ", " + argument + " on " +
				Thread.currentThread());
			return checkInterrupt(manager.processEvent(event));
		}
		if (flags.contains(ChangeEngineState.CURRENT_THREAD)) {
			Msg.info(this, "***CurrentThread: " + argument);
			return checkInterrupt(manager.processEvent(event));
		}
		if (flags.contains(ChangeEngineState.SYSTEMS)) {
			Msg.info(this, "***Systems: " + argument);
			event.setState(StateType.eStateRunning);
			return checkInterrupt(manager.processEvent(event));
		}
		return checkInterrupt(DebugStatus.NO_CHANGE);
	}
	*/

	//@Override
	//public DebugStatus changeDebuggeeState(BitmaskSet<ChangeDebuggeeState> flags, long argument) {
	//	System.err.println("CHANGE_DEBUGGEE_STATE: " + flags + ":" + argument);
	//	return DebugStatus.NO_CHANGE;
	//}

}
