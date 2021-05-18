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

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.cmd.LldbContinueCommand;
import agent.lldb.manager.cmd.LldbStepCommand;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.*;
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

	protected final LldbModelTargetMemoryContainer memory;
	protected final LldbModelTargetThreadContainer threads;
	// Note: not sure section info is available from the Lldbeng
	//protected final LldbModelTargetProcessSectionContainer sections;

	private Integer base = 16;

	public LldbModelTargetProcessImpl(LldbModelTargetProcessContainer processes, SBProcess process) {
		super(processes.getModel(), processes, keyProcess(process), process, "Process");
		this.getModel().addModelObject(DebugClient.getProcessId(process), this);
		getManager().getClient().addBroadcaster(process);

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

		String pidstr = DebugClient.getProcessId(getProcess());
		if (base == 16) {
			pidstr = "0x" + pidstr;
		}
		return "[" + pidstr + "]";
	}

	@Override
	public void processSelected(SBProcess eventProcess, LldbCause cause) {
		if (eventProcess.equals(getProcess())) {
			((LldbModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	public void threadStateChangedSpecific(SBThread thread, StateType state) {
		//TargetExecutionState targetState = convertState(state);
		//setExecutionState(targetState, "ThreadStateChanged");
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		return model.gateFuture(LldbModelImplUtils.launch(getModel(), getProcess(), args));
	}

	@Override
	public CompletableFuture<Void> resume() {
		return getManager().execute(new LldbContinueCommand(getManager(), getProcess()));
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
				PID_ATTRIBUTE_NAME, getProcess().GetProcessID().longValue(), //
				DISPLAY_ATTRIBUTE_NAME, getDisplay()//
			), "Started");
		}
		setExecutionState(TargetExecutionState.ALIVE, "Started");
	}

	@Override
	public void processExited(SBProcess proc, LldbCause cause) {
		if (proc.equals(this.getProcess())) {
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, proc.GetExitDescription() //
			), "Exited");
			getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_EXITED,
				"Process " + DebugClient.getProcessId(getProcess()) + " exited code=" + proc.GetExitDescription(),
				List.of(getProxy()));
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		LldbManagerImpl manager = getManager();
		return manager.setActiveProcess(getProcess());
	}

	@Override
	public LldbModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public SBProcess getProcess() {
		return (SBProcess) getModelObject();
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
