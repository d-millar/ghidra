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

import SWIG.SBProcess;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.manager.LldbEventsListenerAdapter;
import agent.lldb.model.iface1.LldbModelSelectableObject;
import agent.lldb.model.iface1.LldbModelTargetAccessConditioned;
import agent.lldb.model.iface1.LldbModelTargetAttachable;
import agent.lldb.model.iface1.LldbModelTargetAttacher;
import agent.lldb.model.iface1.LldbModelTargetDeletable;
import agent.lldb.model.iface1.LldbModelTargetDetachable;
import agent.lldb.model.iface1.LldbModelTargetExecutionStateful;
import agent.lldb.model.iface1.LldbModelTargetInterruptible;
import agent.lldb.model.iface1.LldbModelTargetKillable;
import agent.lldb.model.iface1.LldbModelTargetLauncher;
import agent.lldb.model.iface1.LldbModelTargetResumable;
import agent.lldb.model.iface1.LldbModelTargetSteppable;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetProcess;

public interface LldbModelTargetProcess extends //
		TargetAggregate, //
		TargetProcess, //
		LldbModelTargetExecutionStateful, //
		LldbModelTargetAccessConditioned, //
		LldbModelTargetAttacher, //
		LldbModelTargetAttachable, //
		LldbModelTargetLauncher, //
		LldbModelTargetDeletable, //
		LldbModelTargetDetachable, //
		LldbModelTargetKillable, //
		LldbModelTargetResumable, //
		LldbModelTargetSteppable, //
		LldbModelTargetInterruptible, // 
		LldbEventsListenerAdapter, //
		LldbModelSelectableObject {

	public void processStarted(SBProcess proc);

	public LldbModelTargetThreadContainer getThreads();

	public void threadStateChangedSpecific(SBThread thread, StateType state);

	public default SBProcess getProcess() {
		/*
		DbgManagerImpl manager = getManager();
		DebugSystemObjects so = manager.getSystemObjects();
		try {
			String index = PathUtils.parseIndex(getName());
			Integer pid = Integer.decode(index);
			DebugProcessId id = so.getProcessIdBySystemId(pid);
			if (id == null) {
				id = so.getCurrentProcessId();
			}
			return manager.getProcessComputeIfAbsent(id, pid);
		}
		catch (IllegalArgumentException e) {
			return manager.getCurrentProcess();
		}
		*/
		return null;
	}

	@Override
	public default CompletableFuture<Void> setActive() {
		/*
		DbgManagerImpl manager = getManager();
		DbgProcess process = getProcess();
		if (process == null) {
			process = manager.getEventProcess();
		}
		return manager.setActiveProcess(process);
		*/
		return AsyncUtils.NIL;
	}

}
