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

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;

import SWIG.SBThread;
import agent.lldb.manager.LldbRegister;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgStackFrameOperations#readRegisters(Set)}
 */
public class LldbWriteRegistersCommand extends AbstractLldbCommand<Void> {

	private final SBThread thread;
	private final Map<LldbRegister, BigInteger> regVals;

	public LldbWriteRegistersCommand(LldbManagerImpl manager, SBThread thread, Integer frameId,
			Map<LldbRegister, BigInteger> regVals) {
		super(manager);
		this.thread = thread;
		this.regVals = regVals;
	}

	@Override
	public void invoke() {
		/*
		DebugSystemObjects so = manager.getSystemObjects();
		DebugThreadId previous = so.getCurrentThreadId();
		so.setCurrentThreadId(thread.getId());
		DebugRegisters registers = manager.getRegisters();
		Map<Integer, DebugValue> values = new LinkedHashMap<>();
		for (LldbRegister r : regVals.keySet()) {
			try {
				BigInteger val = regVals.get(r);
				DebugRegisterDescription desc = registers.getDescription(r.getNumber());
				byte[] bytes = new byte[desc.type.byteLength];
				byte[] newBytes = val.toByteArray();
				for (int i = newBytes.length - 1, j = bytes.length - 1; i >= 0 &&
					j >= 0; i--, j--) {
					bytes[j] = newBytes[i];
				}
				DebugValue dv = desc.type.decodeBytes(bytes);
				values.put(r.getNumber(), dv);
			}
			catch (COMException e) {
				manager.getControl().errln("No register: " + r.getName());
			}
		}
		registers.setValues(DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE, values);
		*/
		//so.setCurrentThreadId(previous);
	}
}
