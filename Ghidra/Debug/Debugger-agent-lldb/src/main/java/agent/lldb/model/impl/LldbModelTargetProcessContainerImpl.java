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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import SWIG.SBProcess;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugModuleInfo;
import agent.lldb.lldb.DebugProcessId;
import agent.lldb.lldb.DebugThreadId;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.model.iface1.LldbModelTargetConfigurable;
import agent.lldb.model.iface2.LldbModelTargetModuleContainer;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import agent.lldb.model.iface2.LldbModelTargetProcessContainer;
import agent.lldb.model.iface2.LldbModelTargetSession;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(name = "ProcessContainer", elements = { //
	@TargetElementType(type = LldbModelTargetProcessImpl.class) //
}, attributes = { //
	@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
	@TargetAttributeType(type = Void.class) //
}, canonicalContainer = true)
public class LldbModelTargetProcessContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetProcessContainer, LldbModelTargetConfigurable {

	public LldbModelTargetProcessContainerImpl(LldbModelTargetSession session) {
		super(session.getModel(), session, "Processes", "ProcessContainer");
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void processAdded(SBProcess proc, LldbCause cause) {
		LldbModelTargetSession session = (LldbModelTargetSession) getParent();
		session.setAccessible(true);
		LldbModelTargetProcess process = getTargetProcess(proc);
		changeElements(List.of(), List.of(process), Map.of(), "Added");
		/*
		process.processStarted(proc.getPid());
		getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_CREATED,
			"Process " + proc.getId() + " started " + process.getName() + "pid=" + proc.getPid(),
			List.of(process));
		*/
	}

	@Override
	public void processStarted(SBProcess proc, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(proc);
		//process.processStarted(proc.getPid());
	}

	@Override
	public void processRemoved(DebugProcessId processId, LldbCause cause) {
		changeElements(List.of( //
			LldbModelTargetProcessImpl.indexProcess(processId) //
		), List.of(), Map.of(), "Removed");
	}

	@Override
	public void threadCreated(SBThread thread, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(thread.GetProcess());
		process.getThreads().threadCreated(thread);
	}

	@Override
	public void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
			LldbReason reason) {
		LldbModelTargetProcess process = getTargetProcess(thread.GetProcess());
		process.threadStateChangedSpecific(thread, state);
	}

	@Override
	public void threadExited(DebugThreadId threadId, SBProcess proc, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(proc);
		if (process != null) {
			//process.getThreads().threadExited(threadId);
		}
	}

	@Override
	public void moduleLoaded(SBProcess proc, DebugModuleInfo info, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(proc);
		LldbModelTargetModuleContainer modules = process.getModules();
		if (modules != null) {
			modules.libraryLoaded(info.toString());
		}
	}

	@Override
	public void moduleUnloaded(SBProcess proc, DebugModuleInfo info, LldbCause cause) {
		LldbModelTargetProcess process = getTargetProcess(proc);
		process.getModules().libraryUnloaded(info.toString());
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return getManager().listProcesses().thenAccept(byIID -> {
			List<TargetObject> processes;
			synchronized (this) {
				processes = byIID.values()
						.stream()
						.map(this::getTargetProcess)
						.collect(Collectors.toList());
			}
			setElements(processes, Map.of(), "Refreshed");
		});
	}

	@Override
	public synchronized LldbModelTargetProcess getTargetProcess(DebugProcessId id) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(id);
		if (modelObject != null) {
			return (LldbModelTargetProcess) modelObject;
		}
		return new LldbModelTargetProcessImpl(this, getManager().getKnownProcesses().get(id));
	}

	@Override
	public synchronized LldbModelTargetProcess getTargetProcess(SBProcess process) {
		LldbModelImpl impl = (LldbModelImpl) model;
		TargetObject modelObject = impl.getModelObject(process);
		if (modelObject != null) {
			return (LldbModelTargetProcess) modelObject;
		}
		return new LldbModelTargetProcessImpl(this, process);
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (TargetObject child : getCachedElements().values()) {
						if (child instanceof LldbModelTargetProcessImpl) {
							LldbModelTargetProcessImpl targetProcess =
								(LldbModelTargetProcessImpl) child;
							targetProcess.setBase(value);
						}
					}
				}
				else {
					throw new DebuggerIllegalArgumentException("Base should be numeric");
				}
			default:
		}
		return AsyncUtils.NIL;
	}

}
