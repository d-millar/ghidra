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

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.LldbModelTargetBreakpointLocation;
import agent.lldb.model.iface2.LldbModelTargetBreakpointSpec;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(
	name = "BreakpointLocation", 
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetBreakpointLocationImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetBreakpointLocation {

	protected static String keyLocation(SBBreakpointLocation loc) {
		return PathUtils.makeKey(DebugClient.getId(loc));
	}

	private LldbModelTargetBreakpointSpec spec;
	protected SBBreakpointLocation loc;
	
	protected Address address;
	protected Integer length;
	protected String display;

	public LldbModelTargetBreakpointLocationImpl(LldbModelTargetBreakpointSpecImpl spec,
			SBBreakpointLocation loc) {
		super(spec.getModel(), spec, keyLocation(loc), loc, "BreakpointLocation");
		this.spec = spec;
		this.loc = loc;
		
		doChangeAttributes("Initialization");
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBBreakpointLocation loc = (SBBreakpointLocation) getModelObject();		
		DescriptionLevel detail = DescriptionLevel.swigToEnum(level);
		loc.GetDescription(stream, detail);
		return stream.GetData();
	}
	
	protected void doChangeAttributes(String reason) {
		address = getModel().getAddress("ram", loc.GetLoadAddress().longValue());
		length = 1;
		this.changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, parent,
			ADDRESS_ATTRIBUTE_NAME, address,
			LENGTH_ATTRIBUTE_NAME, length,
			DISPLAY_ATTRIBUTE_NAME, display = getDescription(0)),
			reason);
		placeLocations();
	}
	
	protected void placeLocations() {
		//TODO: FIX THIS
		SBProcess currentProcess = getManager().getCurrentProcess();
		LldbModelTargetProcessImpl process = (LldbModelTargetProcessImpl) getModel().getModelObject(currentProcess);
		process.addBreakpointLocation(this);
	}

	@Override
	public Integer getLength() {
		return length;
	}

	@Override
	public Address getAddress() {
		return address;
	}
}
