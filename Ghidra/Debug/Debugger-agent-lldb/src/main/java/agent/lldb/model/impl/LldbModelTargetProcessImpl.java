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
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Process",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Memory",
			type = LldbModelTargetMemoryContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Threads",
			type = LldbModelTargetThreadContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Breakpoints",
			type = LldbModelTargetBreakpointLocationContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = LldbModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetProcessImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetProcess {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	public static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexProcess(SBProcess process) {
		return DebugClient.getId(process);
	}

	protected static String keyProcess(SBProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}

	protected final LldbModelTargetMemoryContainer memory;
	protected final LldbModelTargetThreadContainer threads;
	protected final LldbModelTargetBreakpointLocationContainer breakpoints;
	// Note: not sure section info is available from the Lldbeng
	//protected final LldbModelTargetProcessSectionContainer sections;

	private Integer base = 16;

	public LldbModelTargetProcessImpl(LldbModelTargetProcessContainer processes,
			SBProcess process) {
		super(processes.getModel(), processes, keyProcess(process), process, "Process");
		getModel().addModelObject(process, this);
		getManager().getClient().addBroadcaster(process);

		this.memory = new LldbModelTargetMemoryContainerImpl(this);
		this.threads = new LldbModelTargetThreadContainerImpl(this);
		this.breakpoints = new LldbModelTargetBreakpointLocationContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			memory, //
			threads, //
			breakpoints //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, LldbModelTargetThreadImpl.SUPPORTED_KINDS //
		), "Initialized");
		setExecutionState(TargetExecutionState.ALIVE, "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void setModelObject(Object modelObject) {
		super.setModelObject(modelObject);
		getModel().addModelObject(modelObject, this);
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBProcess process = (SBProcess) getModelObject();
		process.GetDescription(stream);
		return stream.GetData();
	}

	@Override
	public String getDisplay() {
		String pidstr = DebugClient.getId(getProcess());
		if (base == 16) {
			pidstr = "0x" + pidstr;
		} else {
			pidstr = Long.toString(Long.parseLong(pidstr,16));
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
		return getManager().execute(new LldbStepCommand(getManager(), null, kind, null));
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return getManager().execute(new LldbStepCommand(getManager(), null, null, args));
	}

	@Override
	public void processStarted(SBProcess proc) {
		if (proc != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, getProcess().GetProcessID().longValue(), //
				DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE //
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
				"Process " + DebugClient.getId(getProcess()) + " exited code=" +
					proc.GetExitDescription(),
				List.of(getProxy()));
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return getManager().setActiveProcess(getProcess());
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

	public void addBreakpointLocation(LldbModelTargetBreakpointLocation loc) {
		breakpoints.addBreakpointLocation(loc);
	}

	public void removeBreakpointLocation(LldbModelTargetBreakpointLocation loc) {
		breakpoints.removeBreakpointLocation(loc);
	}

}
