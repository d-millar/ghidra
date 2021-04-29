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

import SWIG.SBThread;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.AbstractLldbCompletedCommandEvent;
import agent.lldb.manager.evt.LldbRunningEvent;
import agent.lldb.manager.evt.LldbThreadCreatedEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgProcess#fileExecAndSymbols(String)}
 */
public class LldbRunCommand extends AbstractLldbCommand<SBThread> {

	public LldbRunCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			pending.claim(evt);
			return true;
		}
		else if (evt instanceof LldbRunningEvent) {
			pending.claim(evt);
		}
		else if (evt instanceof LldbThreadCreatedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public SBThread complete(LldbPendingCommand<?> pending) {
		/*
		// Just take the first thread. Others are considered clones.
		LldbThreadCreatedEvent created = pending.findFirstOf(LldbThreadCreatedEvent.class);
		DebugThreadInfo info = created.getInfo();
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId tid = so.getThreadIdByHandle(info.handle);
		return manager.getThread(tid);
		*/
		return null;
	}

	@Override
	public void invoke() {
		// TODO Auto-generated method stub
	}
}
