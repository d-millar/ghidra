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

import SWIG.SBTarget;

/**
 * The event corresponding with "{@code =thread-selected}"
 */
public class LldbSessionSelectedEvent extends AbstractLldbEvent<Integer> {
	private final Integer id;
	private SBTarget session;

	/**
	 * The selected session ID must be specified by dbgeng.
	 * 
	 * @param session dbgeng-defined session
	 */
	public LldbSessionSelectedEvent(SBTarget session) {
		super((int) session.GetProcess().GetUniqueID());
		this.session = session;
		this.id = (int) session.GetProcess().GetUniqueID();
	}

	/**
	 * Get the selected session ID
	 * 
	 * @return the session ID
	 */
	public Integer getSessionId() {
		return id;
	}

	public SBTarget getSession() {
		return session;
	}

}
