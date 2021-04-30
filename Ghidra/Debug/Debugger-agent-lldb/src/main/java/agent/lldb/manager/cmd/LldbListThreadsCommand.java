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
import SWIG.SBThread;
import agent.lldb.manager.impl.LldbManagerImpl;
import ghidra.util.Msg;

public class LldbListThreadsCommand extends AbstractLldbCommand<Map<Integer, SBThread>> {
	protected final SBProcess process;
	private List<Integer> updatedThreadIds;

	public LldbListThreadsCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Map<Integer, SBThread> complete(LldbPendingCommand<?> pending) {
		Map<Integer, SBThread> threads = manager.getKnownThreads();
		Set<Integer> cur = threads.keySet();
		for (Integer id : updatedThreadIds) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			Msg.warn(this, "Resync: Was missing thread: " + id);
		}
		for (Integer id : new ArrayList<>(cur)) {
			if (updatedThreadIds.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the thread as if we received =thread-exited
			Msg.warn(this, "Resync: Had extra thread: " + id);
			manager.removeThread(id);
		}
		return manager.getKnownThreads();
	}

	@Override
	public void invoke() {
		long n = process.GetNumThreads();
		for (int i = 0; i < n; i++) {
			SBThread thread = process.GetThreadByIndexID(i);
			updatedThreadIds.add(thread.GetThreadID().intValue());
		}
	}

}
