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

import java.util.HashMap;
import java.util.Map;

import SWIG.SBFrame;
import SWIG.SBValue;
import SWIG.SBValueList;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListStackFrameRegisterBanksCommand extends AbstractLldbCommand<Map<Integer, SBValue>> {
	protected final SBFrame frame;
	private Map<Integer, SBValue> result;

	public LldbListStackFrameRegisterBanksCommand(LldbManagerImpl manager, SBFrame frame) {
		super(manager);
		this.frame = frame;
	}

	@Override
	public Map<Integer, SBValue> complete(LldbPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		result = new HashMap<>();
		SBValueList registers = frame.GetRegisters();
		long n = registers.GetSize();
		for (int i = 0; i < n; i++) {
			result.put(i, registers.GetValueAtIndex(i));
		}
	}
}
