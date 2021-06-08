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
package agent.lldb.model.iface2;

import SWIG.SBValue;
import agent.lldb.model.impl.LldbModelTargetStackFrameRegisterImpl;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "RegisterValueBankNullInterface",
	elementResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = LldbModelTargetStackFrameRegisterImpl.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public interface LldbModelTargetStackFrameRegisterNullBank
		extends LldbModelTargetObject {

	public LldbModelTargetRegister getTargetRegister(SBValue register);

}