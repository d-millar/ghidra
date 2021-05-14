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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.SBModule;
import SWIG.SBTarget;
import agent.lldb.lldb.DebugModuleInfo;
import agent.lldb.model.iface2.LldbModelTargetModule;
import agent.lldb.model.iface2.LldbModelTargetModuleContainer;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetThread;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.lifecycle.Internal;

@TargetObjectSchemaInfo(name = "ModuleContainer", elements = { //
	@TargetElementType(type = LldbModelTargetModuleImpl.class) //
}, //
elementResync = ResyncMode.ONCE, //
attributes = { //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetModuleContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModuleContainer {
	// NOTE: -file-list-shared-libraries omits the main module and system-supplied DSO.

	protected final LldbModelTargetSessionImpl targetSession;
	protected final SBTarget session;

	public LldbModelTargetModuleContainerImpl(LldbModelTargetSessionImpl session) {
		super(session.getModel(), session, "Modules", "ModuleContainer");
		this.targetSession = session;
		this.session = session.session;
		requestElements(false);
	}

	@Override
	@Internal
	public void libraryLoaded(DebugModuleInfo info, int index) {
		LldbModelTargetModule targetModule;
		SBModule module = info.getModule(index);
		synchronized (this) {
			/**
			 * It's not a good idea to remove "stale" entries. If the entry's already present, it's
			 * probably because several modules were loaded at once, at it has already had its
			 * sections loaded. Removing it will cause it to load all module sections again!
			 */
			//modulesByName.remove(name);
			targetModule = getTargetModule(module);
		}
		if (targetModule == null) {
			System.err.println("Module "+info.getModuleName(index)+" not found!");
			return;
		}
		TargetThread eventThread =
			(TargetThread) getModel().getModelObject(getManager().getEventThread());
		changeElements(List.of(), List.of(targetModule), Map.of(), "Loaded");
		getListeners().fire.event(getProxy(), eventThread, TargetEventType.MODULE_LOADED,
			"Library " + info.getModuleName(index) + " loaded", List.of(targetModule));
	}

	@Override
	@Internal
	public void libraryUnloaded(DebugModuleInfo info, int index) {
		LldbModelTargetModule targetModule = getTargetModule(info.getModule(index));
		if (targetModule != null) {
			TargetThread eventThread =
				(TargetThread) getModel().getModelObject(getManager().getEventThread());
			getListeners().fire.event(getProxy(), eventThread, TargetEventType.MODULE_UNLOADED,
				"Library " + info.getModuleName(index) + " unloaded", List.of(targetModule));
			LldbModelImpl impl = (LldbModelImpl) model;
			impl.deleteModelObject(targetModule.getModule());
		}
		changeElements(List.of(info.getModuleName(index)), List.of(), Map.of(), "Unloaded");
	}

	@Override
	public boolean supportsSyntheticModules() {
		return false;
	}

	@Override
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name) {
		throw new UnsupportedOperationException("lldb does not support synthetic modules");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listModules(session).thenAccept(byName -> {
			List<LldbModelTargetModule> result = new ArrayList<>();
			synchronized (this) {
				for (Map.Entry<String, SBModule> ent : byName.entrySet()) {
					result.add(getTargetModule(ent.getValue()));
				}
			}
			changeElements(List.of(), result, Map.of(), "Refreshed");
		});
	}

	public LldbModelTargetModule getTargetModule(SBModule module) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(module);
		if (modelObject != null) {
			return (LldbModelTargetModule) modelObject;
		}
		return new LldbModelTargetModuleImpl(this, module);
	}

}
