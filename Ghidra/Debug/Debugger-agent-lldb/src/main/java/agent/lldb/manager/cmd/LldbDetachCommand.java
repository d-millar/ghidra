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
import java.util.Collection;

import SWIG.SBProcess;
import SWIG.SBThread;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgProcess#kill()}
 */
public class LldbDetachCommand extends AbstractLldbCommand<Void> {
	private final SBProcess process;

	public LldbDetachCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Void complete(LldbPendingCommand<?> pending) {
		/*
		// TODO: necessary?
		Collection<SBThread> threads = new ArrayList<>(process.getKnownThreadsImpl().values());
		for (SBThread t : threads) {
			manager.fireThreadExited(t.getId(), process, pending);
			t.remove();
		}
		manager.getEventListeners().fire.processRemoved(process.getId(), DbgCause.Causes.UNCLAIMED);
		*/
		return null;
	}

	@Override
	public void invoke() {
		/*
		DebugClient dbgeng = manager.getClient();
		dbgeng.detachCurrentProcess();
		*/
	}
}
