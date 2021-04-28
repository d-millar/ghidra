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

import SWIG.StateType;
import agent.lldb.manager.LldbEvent;

/**
 * The event corresponding with "{@code ^error}"
 */
public class LldbCommandErrorEvent extends AbstractLldbCompletedCommandEvent {

	/**
	 * Construct a new event using the given error message
	 * 
	 * @param message the message
	 * @return the new event
	 */
	public static LldbEvent<?> fromMessage(String message) {
		return new LldbCommandErrorEvent(message);
	}

	protected LldbCommandErrorEvent() {
		super();
	}

	protected LldbCommandErrorEvent(String message) {
		super(message);
	}

	@Override
	public StateType newState() {
		return StateType.eStateStopped;
	}
}
