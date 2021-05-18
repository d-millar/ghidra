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

import agent.lldb.model.iface2.LldbModelTargetAvailable;
import agent.lldb.model.iface2.LldbModelTargetAvailableContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "Available", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetAvailableImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetAvailable {

	protected static String keyAttachable(String pid) {
		return PathUtils.makeKey(pid);
	}

	protected final String pid;

	public LldbModelTargetAvailableImpl(LldbModelTargetAvailableContainer parent, String pid,
			String name) {
		super(parent.getModel(), parent, keyAttachable(pid), name);
		this.pid = pid;

		this.changeAttributes(List.of(), List.of(), Map.of(//
			PID_ATTRIBUTE_NAME, Long.parseLong(pid, 16), //
			DISPLAY_ATTRIBUTE_NAME, keyAttachable(pid) + " : " + name.trim() //
		), "Initialized");
	}

	public LldbModelTargetAvailableImpl(LldbModelTargetAvailableContainer parent, String pid) {
		super(parent.getModel(), parent, keyAttachable(pid), "Attachable");
		this.pid = pid;

		this.changeAttributes(List.of(), List.of(), Map.of(//
			PID_ATTRIBUTE_NAME, Long.parseLong(pid, 16), //
			DISPLAY_ATTRIBUTE_NAME, keyAttachable(pid) //
		), "Initialized");
	}

	@TargetAttributeType(name = PID_ATTRIBUTE_NAME, hidden = true)
	@Override
	public Long getPid() {
		return Long.parseLong(pid);
	}

	public void setBase(Object value) {
		this.changeAttributes(List.of(), List.of(), Map.of(//
			DISPLAY_ATTRIBUTE_NAME, keyAttachable(pid) //
		), "Initialized");
	}

}
