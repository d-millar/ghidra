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
package agent.lldb.manager.evt;

import SWIG.SBFrame;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugClient;

/**
 * The event corresponding with "{@code =thread-selected}"
 */
public class LldbThreadSelectedEvent extends AbstractLldbEvent<String> {
	private final String id;
	private StateType state;
	private SBThread thread;
	private SBFrame frame;

	/**
	 * The selected thread ID must be specified by dbgeng.
	 * 
	 * @param frame
	 * @param id dbgeng-provided id
	 */
	public LldbThreadSelectedEvent(StateType state, SBThread thread, SBFrame frame) {
		super(DebugClient.getId(thread));
		this.id = DebugClient.getId(thread);
		this.state = state;
		this.thread = thread;
		this.frame = frame;
	}

	/**
	 * Get the selected thread ID
	 * 
	 * @return the thread ID
	 */
	public String getThreadId() {
		return id;
	}

	public StateType getState() {
		return state;
	}

	public SBThread getThread() {
		return thread;
	}

	public SBFrame getFrame() {
		return frame;
	}

}
