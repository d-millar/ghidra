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

import agent.lldb.manager.LldbCommand;

/**
 * Exception generated by the default "^error" handler
 */
public class LldbCommandError extends RuntimeException {
	private final Object info;

	/**
	 * Construct an error with the given details
	 * 
	 * @param info the detail information
	 * @param cmd source of error
	 */
	public LldbCommandError(Object info, LldbCommand<?> cmd) {
		super(cmd + " caused '" + info + "'");
		this.info = info;
	}

	/**
	 * Construct an error with the given message
	 * 
	 * @param message the message
	 */
	public LldbCommandError(String message) {
		super(message);
		this.info = null;
	}

	/**
	 * Get the details, if present
	 * 
	 * @return the details, or null
	 */
	public Object getInfo() {
		return info;
	}
}
