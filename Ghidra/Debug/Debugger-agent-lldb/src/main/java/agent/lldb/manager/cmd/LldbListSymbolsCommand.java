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

import SWIG.*;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListSymbolsCommand extends AbstractLldbCommand<Map<String, SBSymbol>> {
	protected final SBProcess process;
	protected final SBModule module;

	//private Map<DebugSymbolId, DebugSymbolEntry> symbolEntries = new HashMap<>();

	public LldbListSymbolsCommand(LldbManagerImpl manager, SBProcess process,
			SBModule module) {
		super(manager);
		this.process = process;
		this.module = module;
	}

	@Override
	public Map<String, SBSymbol> complete(LldbPendingCommand<?> pending) {
		Map<String, SBSymbol> symbolMap = new HashMap<>();
		/*
		for (Entry<DebugSymbolId, DebugSymbolEntry> entry : symbolEntries.entrySet()) {
			DebugSymbolEntry value = entry.getValue();
			SBSymbol minSymbol = new SBSymbol(entry.getKey().symbolIndex,
				value.typeId, value.name, value.offset, value.size, value.tag, value.moduleBase);
			symbolMap.put(entry.getKey().toString(), minSymbol);
		}
		*/
		return symbolMap;
	}

	@Override
	public void invoke() {
		/*
		DebugSystemObjects so = manager.getSystemObjects();
		so.setCurrentProcessId(process.getId());
		DebugSymbols symbols = manager.getSymbols();
		
		for (DebugSymbolName symbol : symbols.iterateSymbolMatches(module.getName() + "!*")) {
			List<DebugSymbolId> symbolIdsByName = symbols.getSymbolIdsByName(symbol.name);
			for (DebugSymbolId symbolId : symbolIdsByName) {
				DebugSymbolEntry symbolEntry = symbols.getSymbolEntry(symbolId);
				symbolEntries.put(symbolId, symbolEntry);
			}
		}
		*/
	}
}
