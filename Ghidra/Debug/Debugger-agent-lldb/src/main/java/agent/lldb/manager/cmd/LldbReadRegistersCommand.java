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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import SWIG.SBThread;
import agent.lldb.manager.LldbRegister;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link DbgStackFrameOperations#readRegisters(Set)}
 */
public class LldbReadRegistersCommand extends AbstractLldbCommand<Map<LldbRegister, BigInteger>> {

	private final SBThread thread;
	private final Set<LldbRegister> regs;
	//private DebugRegisters registers;
	private Integer previous;

	public LldbReadRegistersCommand(LldbManagerImpl manager, SBThread thread, Integer frameId,
			Set<LldbRegister> regs) {
		super(manager);
		this.thread = thread;
		this.regs = regs;
	}

	@Override
	public Map<LldbRegister, BigInteger> complete(LldbPendingCommand<?> pending) {
		Map<LldbRegister, BigInteger> result = new LinkedHashMap<>();
		/*
		DebugSystemObjects so = manager.getSystemObjects();
		if (regs.isEmpty()) {
			return Collections.emptyMap();
		}
		for (LldbRegister r : regs) {
			if (registers != null) {
				DebugValue value = registers.getValueByName(r.getName());
				if (value != null) {
					BigInteger bval = new BigInteger(value.encodeAsBytes());
					result.put(r, bval);
				}
			}
		}
		*/
		//so.setCurrentThreadId(previous);
		return result;
	}

	@Override
	public void invoke() {
		/*
		DebugSystemObjects so = manager.getSystemObjects();
		previous = so.getCurrentThreadId();
		so.setCurrentThreadId(thread.getId());
		registers = manager.getClient().getRegisters();
		*/
	}
}
