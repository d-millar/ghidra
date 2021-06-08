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
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.LldbReason;
import agent.lldb.manager.cmd.LldbPendingCommand;

/**
 * A base class for Dbg events
 *
 * @param <T> the type of information detailing the event
 */
public abstract class AbstractLldbEvent<T> implements LldbEvent<T> {
	private final T info;
	protected LldbCause cause = Causes.UNCLAIMED;
	protected boolean stolen = false;
	//protected DebugStatus status = DebugStatus.NO_CHANGE;

	/**
	 * Construct a new event with the given information
	 * 
	 * @param info the information
	 */
	protected AbstractLldbEvent(T info) {
		this.info = info;
	}

	@Override
	public T getInfo() {
		return info;
	}

	@Override
	public void claim(LldbPendingCommand<?> cmd) {
		if (cause != Causes.UNCLAIMED) {
			//throw new IllegalStateException("Event is already claimed by " + cause);
		}
		cause = cmd;
	}

	@Override
	public LldbCause getCause() {
		return cause;
	}

	public LldbReason getReason() {
		return LldbReason.getReason(null);
	}

	@Override
	public void steal() {
		stolen = true;
	}

	@Override
	public boolean isStolen() {
		return stolen;
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + info + " >";
	}

	@Override
	public StateType newState() {
		return null;
	}

}