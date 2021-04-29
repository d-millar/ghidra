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

import SWIG.SBMemoryRegionInfo;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListKernelMemoryRegionsCommand extends AbstractLldbCommand<List<SBMemoryRegionInfo>> {

	private List<SBMemoryRegionInfo> memoryRegions = new ArrayList<>();

	public LldbListKernelMemoryRegionsCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public List<SBMemoryRegionInfo> complete(LldbPendingCommand<?> pending) {
		return memoryRegions;
	}

	@Override
	public void invoke() {
		/*
		SBMemoryRegionInfo section =
			new SBMemoryRegionInfo("lomem", 0L, 0x7FFFFFFFFFFFFFFFL, 0L, new ArrayList<String>(),
				new ArrayList<String>(), PageState.COMMIT, "NONE", true, true, true);
		memoryRegions.add(section);
		section = new SBMemoryRegionInfo("himem", 0x8000000000000000L, 0xFFFFFFFFFFFFFFFFL,
			0x8000000000000000L, new ArrayList<String>(), new ArrayList<String>(), PageState.COMMIT,
			"NONE", true, true, true);
		memoryRegions.add(section);
		DebugDataSpaces dataSpaces = manager.getDataSpaces();
		for (DebugMemoryBasicInformation info : dataSpaces.iterateVirtual(0)) {
			if (info.state == PageState.FREE) {
				continue;
			}
			String type = "[" + info.type + "]";
			if (info.type == PageType.IMAGE) {
				try {
					DebugModule mod = manager.getSymbols().getModuleByOffset(info.baseAddress, 0);
					if (mod != null) {
						type = mod.getName(DebugModuleName.IMAGE);
					}
				}
				catch (COMException e) {
					type = "[IMAGE UNKNOWN]";
				}
			}
			else if (info.type == PageType.MAPPED) {
				// TODO: Figure out the file name
			}
			long vmaStart = info.baseAddress;
			long vmaEnd = info.baseAddress + info.regionSize;
		
			boolean isRead = false;
			boolean isWrite = false;
			boolean isExec = false;
			List<String> ap = new ArrayList<>();
			for (PageProtection protect : info.allocationProtect) {
				ap.add(protect.toString());
				isRead |= protect.isRead();
				isWrite |= protect.isWrite();
				isExec |= protect.isExecute();
			}
			List<String> ip = new ArrayList<>();
			for (PageProtection protect : info.protect) {
				ip.add(protect.toString());
				isRead |= protect.isRead();
				isWrite |= protect.isWrite();
				isExec |= protect.isExecute();
			}
			LldbModuleMemoryImpl section =
				new LldbModuleMemoryImpl(Long.toHexString(vmaStart), vmaStart, vmaEnd,
					info.allocationBase, ap, ip, info.state, type, isRead, isWrite, isExec);
			memoryRegions.add(section);
		}
		*/
	}

}
