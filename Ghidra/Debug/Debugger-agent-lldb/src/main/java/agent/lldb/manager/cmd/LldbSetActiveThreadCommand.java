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
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbSetActiveThreadCommand extends AbstractLldbCommand<Void> {

	private SBThread thread;
	private Integer frameId;

	/**
	 * Set the active thread
	 * 
	 * @param manager the manager to execute the command
	 * @param thread the desired thread
	 * @param frameId the desired frame level
	 */
	public LldbSetActiveThreadCommand(LldbManagerImpl manager, SBThread thread, Integer frameId) {
		super(manager);
		this.thread = thread;
		this.frameId = frameId;
	}

	@Override
	public void invoke() {
		/*
		DebugThreadId id = thread.GetIndexID();
		if (id != null) {
			manager.getSystemObjects().setCurrentThreadId(id);
			if (frameId != null) {
				manager.getSymbols().setCurrentScopeFrameIndex(frameId);
			}
		}
		*/
	}
}
