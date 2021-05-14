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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBModule;
import SWIG.SBSection;
import agent.lldb.model.iface2.LldbModelTargetModule;
import agent.lldb.model.iface2.LldbModelTargetModuleSection;
import agent.lldb.model.iface2.LldbModelTargetModuleSectionContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(name = "SectionContainer", elements = {
	@TargetElementType(type = LldbModelTargetModuleSectionImpl.class) }, attributes = {
		@TargetAttributeType(type = Void.class) }, canonicalContainer = true)
public class LldbModelTargetModuleSectionContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModuleSectionContainer {

	protected final SBModule module;

	public LldbModelTargetModuleSectionContainerImpl(LldbModelTargetModule module) {
		super(module.getModel(), module, "Sections", "ModuleSections");
		this.module = module.getModule();

	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listModuleSections(module).thenAccept(byStart -> {
			List<TargetObject> sections;
			synchronized (this) {
				sections = byStart.values()
						.stream()
						.map(this::getModuleSection)
						.collect(Collectors.toList());
				setElements(sections, "Refreshed");
			}
		});
	}

	protected synchronized LldbModelTargetModuleSection getModuleSection(SBSection section) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(section);
		if (modelObject != null) {
			return (LldbModelTargetModuleSection) modelObject;
		}
		return new LldbModelTargetModuleSectionImpl(this, section);
	}

}
