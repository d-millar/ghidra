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

import SWIG.SBProcess;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.cmd.LldbContinueCommand;
import agent.lldb.manager.cmd.LldbListProcessesCommand;
import agent.lldb.manager.cmd.LldbStepCommand;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.LldbModelTargetDebugContainer;
import agent.lldb.model.iface2.LldbModelTargetMemoryContainer;
import agent.lldb.model.iface2.LldbModelTargetModuleContainer;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import agent.lldb.model.iface2.LldbModelTargetProcessContainer;
import agent.lldb.model.iface2.LldbModelTargetThreadContainer;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "Process", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Memory", type = LldbModelTargetMemoryContainerImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = "Threads", type = LldbModelTargetThreadContainerImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = LldbModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetProcessImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetProcess {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	public static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexProcess(SBProcess process) {
		return DebugClient.getProcessId(process);
	}

	protected static String keyProcess(SBProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}

	protected final SBProcess process;

	protected final LldbModelTargetMemoryContainer memory;
	protected final LldbModelTargetThreadContainer threads;
	// Note: not sure section info is available from the Lldbeng
	//protected final LldbModelTargetProcessSectionContainer sections;

	private Integer base = 16;

	public LldbModelTargetProcessImpl(LldbModelTargetProcessContainer processes, SBProcess process) {
		super(processes.getModel(), processes, keyProcess(process), "Process");
		this.getModel().addModelObject(process, this);
		getManager().getClient().addBroadcaster(process);
		this.process = process;

		this.memory = new LldbModelTargetMemoryContainerImpl(this);
		//this.sections = new LldbModelTargetProcessSectionContainerImpl(this);
		this.threads = new LldbModelTargetThreadContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			memory, //
			//sections, //
			threads //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, LldbModelTargetThreadImpl.SUPPORTED_KINDS //
		), "Initialized");
		setExecutionState(TargetExecutionState.ALIVE, "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public String getDisplay() {
		if (getManager().isKernelMode()) {
			return "[kernel]";
		}

		String pidstr = DebugClient.getProcessId(process);
		if (base == 16) {
			pidstr = "0x" + pidstr;
		}
		return "[" + pidstr + "]";
	}

	@Override
	public void processSelected(SBProcess eventProcess, LldbCause cause) {
		if (eventProcess.equals(process)) {
			((LldbModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	public void threadStateChangedSpecific(SBThread thread, StateType state) {
		//TargetExecutionState targetState = convertState(state);
		//setExecutionState(targetState, "ThreadStateChanged");
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		return model.gateFuture(LldbModelImplUtils.launch(getModel(), process, args));
	}

	@Override
	public CompletableFuture<Void> resume() {
		return getManager().execute(new LldbContinueCommand(getManager(), process));
		//return model.gateFuture(process.cont());
	}

	@Override
	public CompletableFuture<Void> kill() {
		return null; //model.gateFuture(process.kill());
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		getModel().assertMine(TargetObject.class, attachable);
		// NOTE: Get the object and type check it myself.
		// The typed ref could have been unsafely cast
		return null; //model.gateFuture(process.reattach(attachable)).thenApply(set -> null);
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return null; //model.gateFuture(process.attach(pid)).thenApply(set -> null);
	}

	@Override
	public CompletableFuture<Void> detach() {
		return null; //model.gateFuture(process.detach());
	}

	@Override
	public CompletableFuture<Void> delete() {
		return null; //model.gateFuture(process.remove());
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in Lldbeng?
				throw new UnsupportedOperationException(kind.name());
			default:
				return getManager().execute(new LldbStepCommand(getManager(), 0, null));
		}
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return getManager().execute(new LldbStepCommand(getManager(), 0, null));
	}

	@Override
	public void processStarted(SBProcess proc) {
		if (proc != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, Long.valueOf(DebugClient.getProcessId(process)), //
				DISPLAY_ATTRIBUTE_NAME, getDisplay()//
			), "Started");
		}
		setExecutionState(TargetExecutionState.ALIVE, "Started");
	}

	@Override
	public void processExited(SBProcess proc, LldbCause cause) {
		if (proc.equals(this.process)) {
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, proc.GetExitDescription() //
			), "Exited");
			getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_EXITED,
				"Process " + DebugClient.getProcessId(process) + " exited code=" + proc.GetExitDescription(),
				List.of(getProxy()));
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		LldbManagerImpl manager = getManager();
		return manager.setActiveProcess(process);
	}

	@Override
	public LldbModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public SBProcess getProcess() {
		return process;
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}
}
