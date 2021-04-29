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

import SWIG.SBTarget;
import agent.lldb.lldb.DebugSessionId;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link DbgManager#listSessions()}
 */
public class LldbListSessionsCommand extends AbstractLldbCommand<Map<DebugSessionId, SBTarget>> {
	private List<DebugSessionId> updatedSessionIds = new ArrayList<>();

	public LldbListSessionsCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<DebugSessionId, SBTarget> complete(LldbPendingCommand<?> pending) {
		Map<DebugSessionId, SBTarget> allSessions = manager.getKnownSessions();
		Set<DebugSessionId> cur = allSessions.keySet();
		for (DebugSessionId id : updatedSessionIds) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the inferior as if we received =thread-group-created
			Msg.warn(this, "Resync: Was missing group: i" + id);
			manager.getSessionComputeIfAbsent(id);
		}
		for (DebugSessionId id : new ArrayList<>(cur)) {
			if (updatedSessionIds.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the session as if we received =thread-group-removed
			Msg.warn(this, "Resync: Had extra group: i" + id);
			manager.removeSession(id, Causes.UNCLAIMED);
		}
		return allSessions;
	}

	@Override
	public void invoke() {
		//DebugSystemObjects so = manager.getSystemObjects();
		//updatedSessionIds = so.getSessions();
	}
}
