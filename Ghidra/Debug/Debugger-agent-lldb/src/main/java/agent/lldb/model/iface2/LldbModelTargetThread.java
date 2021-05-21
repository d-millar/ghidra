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
package agent.lldb.model.iface2;

import java.util.concurrent.CompletableFuture;

import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.manager.*;
import agent.lldb.manager.cmd.LldbSetActiveThreadCommand;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface1.LldbModelSelectableObject;
import agent.lldb.model.iface1.LldbModelTargetAccessConditioned;
import agent.lldb.model.iface1.LldbModelTargetExecutionStateful;
import agent.lldb.model.iface1.LldbModelTargetSteppable;
import agent.lldb.model.impl.LldbModelTargetStackImpl;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetRegisterContainer;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.util.PathUtils;

public interface LldbModelTargetThread extends //
		TargetThread, //
		LldbModelTargetAccessConditioned, //
		LldbModelTargetExecutionStateful, //
		LldbModelTargetSteppable, //
		LldbStateListener, //
		LldbEventsListenerAdapter, //
		LldbModelSelectableObject {

	public default SBThread getThread() {
		LldbManagerImpl manager = getManager();
		try {
			String index = PathUtils.parseIndex(getName());
			int tid = Integer.decode(index);
			/*
			DebugSystemObjects so = manager.getSystemObjects();
			DebugThreadId id = so.getThreadIdBySystemId(tid);
			if (id == null) {
				id = so.getCurrentThreadId();
			}
			LldbModelTargetProcess parentProcess = getParentProcess();
			SBProcess process = (SBProcess) parentProcess.getProcess();
			SBThread thread = manager.getThreadComputeIfAbsent(id, process, tid);
			return thread;
			*/
			return null;
		}
		catch (IllegalArgumentException e) {
			return manager.getCurrentThread();
		}
	}

	public default void threadStateChangedSpecific(StateType state, LldbReason reason) {
		TargetRegisterContainer container =
			(TargetRegisterContainer) getCachedAttribute("Registers");
		TargetRegisterBank bank = (TargetRegisterBank) container.getCachedAttribute("User");
		if (state.equals(StateType.eStateStopped)) {
			bank.readRegistersNamed(getCachedElements().keySet());
		}
	}

	@Override
	public default CompletableFuture<Void> setActive() {
		LldbManagerImpl manager = getManager();
		SBThread thread = getThread();
		return manager.execute(new LldbSetActiveThreadCommand(manager, thread, -1));
	}

	public LldbModelTargetStackImpl getStack();

	public String getExecutingProcessorType();

}
