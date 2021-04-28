/* ###
s * IP: GHIDRA
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

import SWIG.SBProcess;
import agent.lldb.lldb.DebugProcessId;

/**
 * The event corresponding with "{@code =thread-selected}"
 */
public class LldbProcessSelectedEvent extends AbstractLldbEvent<DebugProcessId> {
	private final DebugProcessId id;
	private SBProcess process;

	/**
	 * The selected process ID must be specified by dbgeng.
	 * 
	 * @param id dbgeng-defined id
	 */
	public LldbProcessSelectedEvent(SBProcess process) {
		super(process.getId());
		this.process = process;
		this.id = process.getId();
	}

	/**
	 * Get the selected process ID
	 * 
	 * @return the process ID
	 */
	public DebugProcessId getProcessId() {
		return id;
	}

	public SBProcess getProcess() {
		return process;
	}

}
