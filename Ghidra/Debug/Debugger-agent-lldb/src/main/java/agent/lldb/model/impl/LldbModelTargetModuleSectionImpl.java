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

import SWIG.SBSection;
import SWIG.SBValue;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.LldbModelTargetModuleSection;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;

@TargetObjectSchemaInfo(name = "Section", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Object.class) })
public class LldbModelTargetModuleSectionImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModuleSection {

	protected static String keySection(SBSection section) {
		return PathUtils.makeKey(section.GetName());
	}

	protected static final String OBJFILE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "objfile";

	protected AddressRange range;

	public LldbModelTargetModuleSectionImpl(LldbModelTargetModuleSectionContainerImpl sections,
			SBSection section) {
		super(sections.getModel(), sections, keySection(section), section, "Section");

		AddressSpace space = getModel().getAddressSpace("ram");
		Address min = space.getAddress(section.GetFileAddress().longValue());
		// Ghidra ranges are not inclusive at the end.
		long sz = section.GetFileAddress().add(section.GetFileByteSize()).longValue() - 1;
		Address max = space.getAddress(sz);
		range = new AddressRangeImpl(min, max);

		changeAttributes(List.of(), List.of(), Map.of( //
			MODULE_ATTRIBUTE_NAME, sections.getParent(), //
			RANGE_ATTRIBUTE_NAME, range, //
			DISPLAY_ATTRIBUTE_NAME, section.GetName(), //
			"Address", min, //
			"Offset", section.GetFileOffset().toString(16), //
			"Size", Long.toHexString(sz), //
			"Permissions", section.GetPermissions() //
		), "Initialized");
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

}
