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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import SWIG.SBProcess;
import SWIG.SBTarget;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link LldbManager#listProcesses()}
 */
public class LldbListProcessesCommand extends AbstractLldbCommand<Map<Integer, SBProcess>> {
	private Map<Integer, SBProcess> updatedProcesses;
	private SBTarget session;

	public LldbListProcessesCommand(LldbManagerImpl manager, SBTarget session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Map<Integer, SBProcess> complete(LldbPendingCommand<?> pending) {
		Map<Integer, SBProcess> allProcesses = manager.getKnownProcesses(session);
		Set<Integer> cur = allProcesses.keySet();
		for (Integer id : updatedProcesses.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			Msg.warn(this, "Resync: Was missing rocess: " + id);
			manager.addProcessIfAbsent(session, updatedProcesses.get(id));
		}
		for (Integer id : new ArrayList<>(cur)) {
			if (updatedProcesses.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the inferior as if we received =thread-group-removed
			Msg.warn(this, "Resync: Had extra process: " + id);
			manager.removeProcess(session, id, Causes.UNCLAIMED);
		}
		return allProcesses;
	}

	@Override
	public void invoke() {	
		SBProcess p = session.GetProcess();
		updatedProcesses = new HashMap<>();
		updatedProcesses.put(DebugClient.getProcessId(p), p);
	}
}
