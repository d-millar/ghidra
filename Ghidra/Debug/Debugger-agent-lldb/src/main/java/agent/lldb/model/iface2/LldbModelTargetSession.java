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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.SBTarget;
import agent.lldb.manager.LldbEventsListenerAdapter;
import agent.lldb.manager.impl.LldbManagerImpl;
import agent.lldb.model.iface1.LldbModelSelectableObject;
import agent.lldb.model.iface1.LldbModelTargetAccessConditioned;
import agent.lldb.model.iface1.LldbModelTargetExecutionStateful;
import agent.lldb.model.iface1.LldbModelTargetInterpreter;
import agent.lldb.model.iface1.LldbModelTargetInterruptible;
import agent.lldb.model.iface1.LldbModelTargetResumable;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetConsole;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.util.PathUtils;

public interface LldbModelTargetSession extends //
		LldbModelTargetAccessConditioned, //
		//LldbModelTargetFocusScope, //
		LldbModelTargetExecutionStateful, //
		LldbModelTargetInterpreter, //
		LldbModelTargetInterruptible, //
		LldbModelTargetResumable, //
		LldbEventsListenerAdapter, //
		LldbModelSelectableObject, //
		TargetAggregate {

	LldbModelTargetProcessContainer getProcesses();

	@Override
	public default void consoleOutput(String output, int mask) {

		Channel chan = TargetConsole.Channel.STDOUT;
		/*
		if (((mask & DebugOutputFlags.DEBUG_OUTPUT_ERROR.getValue()) //
				== DebugOutputFlags.DEBUG_OUTPUT_ERROR.getValue()) || //
			((mask & DebugOutputFlags.DEBUG_OUTPUT_WARNING.getValue()) // 
					== DebugOutputFlags.DEBUG_OUTPUT_WARNING.getValue())) {
			chan = TargetConsole.Channel.STDERR;
		}
		*/
		if (output.contains("loaded *kernel* extension dll for usermode")) {
			return;
		}
		getListeners().fire.consoleOutput(getProxy(), chan, output);
	}

	@Override
	public default void promptChanged(String prompt) {
		changeAttributes(List.of(), Map.of( //
			PROMPT_ATTRIBUTE_NAME, prompt //
		), "Refreshed");
	}

}
