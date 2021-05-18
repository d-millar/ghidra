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

import SWIG.SBFrame;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.manager.cmd.LldbSetActiveThreadCommand;
import agent.lldb.manager.cmd.LldbStepCommand;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.LldbModelTargetProcess;
import agent.lldb.model.iface2.LldbModelTargetRegisterContainerAndBank;
import agent.lldb.model.iface2.LldbModelTargetThread;
import agent.lldb.model.iface2.LldbModelTargetThreadContainer;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "Thread", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Stack", type = LldbModelTargetStackImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = TargetEnvironment.ARCH_ATTRIBUTE_NAME, type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetThreadImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetThread {

	public static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, //
		TargetStepKind.FINISH, //
		TargetStepKind.LINE, //
		TargetStepKind.OVER, //
		TargetStepKind.OVER_LINE, //
		TargetStepKind.RETURN, //
		TargetStepKind.UNTIL, //
		TargetStepKind.EXTENDED);

	protected static String indexThread(Integer id) {
		return PathUtils.makeIndex(id);
	}

	protected static String indexThread(SBThread thread) {
		return DebugClient.getThreadId(thread);
	}

	protected static String keyThread(SBThread thread) {
		return PathUtils.makeKey(indexThread(thread));
	}

	protected final SBThread thread;

	//protected final LldbModelTargetRegisterContainerImpl registers;
	protected final LldbModelTargetStackImpl stack;

	private LldbModelTargetProcess process;
	private Integer base = 16;

	public LldbModelTargetThreadImpl(LldbModelTargetThreadContainer threads,
			LldbModelTargetProcess process, SBThread thread) {
		super(threads.getModel(), threads, keyThread(thread), "Thread");
		this.getModel().addModelObject(DebugClient.getThreadId(thread), this);
		this.process = process;
		this.thread = thread;

		//this.registers = new LldbModelTargetRegisterContainerImpl(this);
		this.stack = new LldbModelTargetStackImpl(this, process);

		changeAttributes(List.of(), List.of( //
			//registers, //
			stack //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");
		//setExecutionState(convertState(thread.getState()), "Initialized");
		// TODO: Stack (Registers)

		getManager().addEventsListener(this);
	}

	@Override
	public String getDisplay() {
		if (getManager().isKernelMode()) {
			return "[PR" +  DebugClient.getThreadId(thread) + "]";
		}
		String tidstr = DebugClient.getThreadId(thread);
		return "[" + tidstr + "]";
	}

	@Override
	public void threadSelected(SBThread eventThread, SBFrame frame, LldbCause cause) {
		if (eventThread.equals(thread)) {
			((LldbModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		/*
		TargetExecutionState targetState = convertState(state);
		String executionType = thread.getExecutingProcessorType().description;
		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState, //
			TargetEnvironment.ARCH_ATTRIBUTE_NAME, executionType //
		), reason.desc());
		*/
		//setExecutionState(targetState, reason.desc());
		//registers.threadStateChangedSpecific(state, reason);
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in GDB/MI?
				return null; //thread.console("advance");
			default:
				return getManager().execute(new LldbStepCommand(getManager(), 0, null));
		}
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return getManager().execute(new LldbStepCommand(getManager(), 0, args));
	}

	@Override
	public CompletableFuture<Void> setActive() {
		LldbManagerImpl manager = getManager();
		return manager.execute(new LldbSetActiveThreadCommand(manager, thread, null));
	}

	public LldbModelTargetRegisterContainerAndBank getRegisters() {
		return null; //registers;
	}

	@Override
	public LldbModelTargetStackImpl getStack() {
		return stack;
	}

	@Override
	public SBThread getThread() {
		return thread;
	}

	public LldbModelTargetProcess getProcess() {
		return process;
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public String getExecutingProcessorType() {
		return null; //thread.getExecutingProcessorType().description;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

}
