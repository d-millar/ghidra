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
package agent.lldb.manager.cmd;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import SWIG.SBProcess;
import agent.lldb.lldb.DebugProcessId;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbManager#listProcesses()}
 */
public class LldbListProcessesCommand extends AbstractLldbCommand<Map<DebugProcessId, SBProcess>> {
	private List<DebugProcessId> updatedProcessIds;

	public LldbListProcessesCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<DebugProcessId, SBProcess> complete(LldbPendingCommand<?> pending) {
		Map<DebugProcessId, SBProcess> allProcesses = manager.getKnownProcesses();
		Set<DebugProcessId> cur = allProcesses.keySet();
		for (DebugProcessId id : updatedProcessIds) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the inferior as if we received =thread-group-created
			Msg.warn(this, "Resync: Was missing group: i" + id);
			DebugSystemObjects so = manager.getSystemObjects();
			so.setCurrentProcessId(id);
			int pid = so.getCurrentProcessSystemId();
			manager.getProcessComputeIfAbsent(id, pid);
		}
		for (DebugProcessId id : new ArrayList<>(cur)) {
			if (updatedProcessIds.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the inferior as if we received =thread-group-removed
			Msg.warn(this, "Resync: Had extra group: i" + id);
			manager.removeProcess(id, Causes.UNCLAIMED);
		}
		return allProcesses;
	}

	@Override
	public void invoke() {
		DebugSystemObjects so = manager.getSystemObjects();
		updatedProcessIds = so.getProcesses();
	}
}
