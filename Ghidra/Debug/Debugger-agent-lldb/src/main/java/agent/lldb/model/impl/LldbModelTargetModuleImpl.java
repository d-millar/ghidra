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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;

import SWIG.SBMemoryRegionInfo;
import SWIG.SBModule;
import SWIG.SBProcess;
import agent.lldb.model.iface2.LldbModelTargetModule;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;

@TargetObjectSchemaInfo(name = "Module", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Symbols", type = LldbModelTargetSymbolContainerImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = "BaseAddress", type = Address.class),
		@TargetAttributeType(name = "ImageName", type = String.class),
		@TargetAttributeType(name = "TimeStamp", type = Integer.class),
		@TargetAttributeType(name = "Len", type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetModuleImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModule {
	protected static String indexModule(SBModule module) {
		return module.getName();
	}

	protected static String keyModule(SBModule module) {
		return PathUtils.makeKey(indexModule(module));
	}

	protected final SBProcess process;
	protected final SBModule module;

	protected final LldbModelTargetSymbolContainerImpl symbols;
	//protected final LldbModelTargetModuleSectionContainerImpl sections;

	public LldbModelTargetModuleImpl(LldbModelTargetModuleContainerImpl modules, SBModule module) {
		super(modules.getModel(), modules, keyModule(module), "Module");
		this.getModel().addModelObject(module, this);
		this.process = modules.process;
		this.module = module;

		this.symbols = new LldbModelTargetSymbolContainerImpl(this);
		//this.sections = new LldbModelTargetModuleSectionContainerImpl(this);

		AddressSpace space = getModel().getAddressSpace("ram");

		changeAttributes(List.of(), List.of( //
			symbols //
		//  sections.getName(), sections, //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getIndex(), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, module.getName(), //
			MODULE_NAME_ATTRIBUTE_NAME, module.getImageName(), //
			"BaseAddress", space.getAddress(module.getKnownBase()), //
			"ImageName", module.getImageName(), //
			"TimeStamp", module.getTimeStamp(), //
			"Len", Integer.toHexString(module.getSize()) //
		), "Initialized");

		SBMemoryRegionInfo section = new SBMemoryRegionInfo(module);
		Address min = space.getAddress(section.getStart());
		// Ghidra ranges are not inclusive at the end.
		Address max = space.getAddress(section.getStart() + section.getSize() - 1);
		AddressRange range = new AddressRangeImpl(min, max);

		changeAttributes(List.of(), List.of(), Map.of( //
			RANGE_ATTRIBUTE_NAME, range //
		), "Initialized");
	}

	protected Address doGetBase() {
		return getModel().getAddressSpace("ram").getAddress(module.getKnownBase());
	}

	@Override
	public SBModule getModule() {
		return module;
	}

	public SBProcess getProcess() {
		return process;
	}

}
