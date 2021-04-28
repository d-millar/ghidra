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

import java.util.Map;

import SWIG.SBThread;
import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.*;
import agent.lldb.lldb.DebugThreadId;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.AbstractLldbCompletedCommandEvent;
import agent.lldb.manager.evt.LldbProcessCreatedEvent;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgProcess#fileExecAndSymbols(String)}
 */
public class LldbAttachKernelCommand extends AbstractLldbCommand<SBThread> {

	private LldbProcessCreatedEvent created = null;
	private boolean completed = false;
	private Map<String, ?> args;

	public LldbAttachKernelCommand(LldbManagerImpl manager, Map<String, ?> args) {
		super(manager);
		this.args = args;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof LldbProcessCreatedEvent) {
			created = (LldbProcessCreatedEvent) evt;
		}
		return completed && (created != null);
	}

	@Override
	public SBThread complete(LldbPendingCommand<?> pending) {
		DebugProcessInfo info = created.getInfo();
		DebugThreadInfo tinfo = info.initialThreadInfo;
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId tid = so.getThreadIdByHandle(tinfo.handle);
		return manager.getThread(tid);
	}

	@Override
	public void invoke() {
		DebugClient dbgeng = manager.getClient();
		long flags = (Long) args.get("Flags");
		String options = (String) args.get("Options");
		dbgeng.attachKernel(flags, options);
		manager.waitForEventEx();
	}
}
