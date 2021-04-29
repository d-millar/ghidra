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

import java.util.List;
import java.util.Map;

import SWIG.SBProcess;
import SWIG.SBThread;
import agent.lldb.lldb.DebugThreadId;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListThreadsCommand extends AbstractLldbCommand<Map<DebugThreadId, SBThread>> {
	protected final SBProcess process;
	private List<DebugThreadId> updatedThreadIds;

	public LldbListThreadsCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Map<DebugThreadId, SBThread> complete(LldbPendingCommand<?> pending) {
		/*
		Map<DebugThreadId, SBThread> threads = process.getKnownThreads();
		Set<DebugThreadId> cur = threads.keySet();
		for (DebugThreadId id : updatedThreadIds) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			Msg.warn(this, "Resync: Was missing thread: " + id);
			DebugSystemObjects so = manager.getSystemObjects();
			so.setCurrentThreadId(id);
			int tid = so.getCurrentThreadSystemId();
			manager.getThreadComputeIfAbsent(id, process, tid);
		}
		for (DebugThreadId id : new ArrayList<>(cur)) {
			if (updatedThreadIds.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the thread as if we received =thread-exited
			Msg.warn(this, "Resync: Had extra thread: " + id);
			process.removeThread(id);
			manager.removeThread(id);
		}
		return process.getKnownThreads();
		*/
		return null;
	}

	@Override
	public void invoke() {
		/*
		DebugSystemObjects so = manager.getSystemObjects();
		so.setCurrentProcessId(process.getId());
		updatedThreadIds = so.getThreads();
		*/
	}

}
