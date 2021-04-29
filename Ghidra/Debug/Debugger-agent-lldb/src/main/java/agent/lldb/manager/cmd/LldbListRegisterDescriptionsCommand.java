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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import agent.lldb.lldb.DebugRegisters;
import agent.lldb.lldb.DebugRegisters.DebugRegisterDescription;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListRegisterDescriptionsCommand
		extends AbstractLldbCommand<List<DebugRegisterDescription>> {

	private List<DebugRegisterDescription> list;

	public LldbListRegisterDescriptionsCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<DebugRegisterDescription> complete(LldbPendingCommand<?> pending) {
		return list;
	}

	@Override
	public void invoke() {
		/*
		DebugRegisters registers = manager.getRegisters();
		Set<DebugRegisterDescription> descs = registers.getAllDescriptions();
		list = new ArrayList<DebugRegisterDescription>();
		for (DebugRegisterDescription desc : descs) {
			list.add(desc);
		}
		*/
	}

}
