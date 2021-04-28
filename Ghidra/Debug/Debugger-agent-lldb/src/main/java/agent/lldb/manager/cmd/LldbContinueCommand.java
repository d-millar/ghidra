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

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.manager.DbgProcess;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.AbstractLldbCompletedCommandEvent;
import agent.lldb.manager.evt.LldbCommandErrorEvent;
import agent.lldb.manager.evt.LldbRunningEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgProcess#kill()}
 */
public class LldbContinueCommand extends AbstractLldbCommand<Void> {
	public LldbContinueCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			return evt instanceof LldbCommandErrorEvent ||
				!pending.findAllOf(LldbRunningEvent.class).isEmpty();
		}
		else if (evt instanceof LldbRunningEvent) {
			// Event happens no matter which interpreter received the command
			pending.claim(evt);
			return !pending.findAllOf(AbstractLldbCompletedCommandEvent.class).isEmpty();
		}
		return false;
	}

	@Override
	public void invoke() {
		DebugClient dbgeng = manager.getClient();
		dbgeng.getControl().setExecutionStatus(DebugStatus.GO);
	}
}
