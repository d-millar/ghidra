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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import SWIG.StateType;
import agent.lldb.manager.LldbReason;
import agent.lldb.manager.LldbRegister;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetRegisterBank;

public interface LldbModelTargetRegisterBank extends LldbModelTargetObject, TargetRegisterBank {

	public LldbModelTargetRegister getTargetRegister(LldbRegister register);

	public default void threadStateChangedSpecific(StateType state, LldbReason reason) {
		readRegistersNamed(getCachedElements().keySet());
	}

	@Override
	public default CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		return getModel().gateFuture(doReadRegistersNamed(names));
	}

	public default CompletableFuture<? extends Map<String, byte[]>> doReadRegistersNamed(
			Collection<String> names) {
		/*
		DbgManagerImpl manager = getManager();
		if (manager.isWaiting()) {
			Msg.warn(this,
				"Cannot process command readRegistersNamed while engine is waiting for events");
		}

		AtomicReference<Map<DbgRegister, LldbModelTargetRegister>> read = new AtomicReference<>();
		return getManager().getRegisterMap(getPath()).thenCompose(valueMap -> {
			Map<String, ?> regs = getCachedAttributes();
			Map<DbgRegister, LldbModelTargetRegister> map =
				new HashMap<DbgRegister, LldbModelTargetRegister>();

			for (String regname : names) {
				Object x = regs.get(regname);
				if (!(x instanceof LldbModelTargetRegister)) {
					continue;
				}
				if (!valueMap.containsKey(regname)) {
					continue;
				}
				LldbModelTargetRegister reg = (LldbModelTargetRegister) x;
				DbgRegister register = (DbgRegister) valueMap.get(regname);
				if (register != null) {
					map.put(register, reg);
				}
			}
			read.set(map);
			return getParentThread().getThread().readRegisters(map.keySet());
		}).thenApply(vals -> {
			Map<String, byte[]> result = new LinkedHashMap<>();
			for (DbgRegister dbgReg : vals.keySet()) {
				LldbModelTargetRegister reg = read.get().get(dbgReg);
				String oldval = (String) reg.getCachedAttributes().get(VALUE_ATTRIBUTE_NAME);
				BigInteger value = vals.get(dbgReg);
				byte[] bytes = ConversionUtils.bigIntegerToBytes(dbgReg.getSize(), value);
				result.put(dbgReg.getName(), bytes);
				reg.changeAttributes(List.of(), Map.of( //
					VALUE_ATTRIBUTE_NAME, value.toString(16) //
				), "Refreshed");
				if (value.longValue() != 0) {
					String newval = reg.getName() + " : " + value.toString(16);
					reg.changeAttributes(List.of(), Map.of( //
						DISPLAY_ATTRIBUTE_NAME, newval //
					), "Refreshed");
					reg.setModified(value.toString(16).equals(oldval));
				}
			}
			ListenerSet<DebuggerModelListener> listeners = getListeners();
			if (listeners != null) {
				listeners.fire.registersUpdated(getProxy(), result);
			}
			return result;
		});
		*/
		return CompletableFuture.completedFuture(null);

	}

	@Override
	public default CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		return getModel().gateFuture(doWriteRegistersNamed(values));
	}

	public default CompletableFuture<Void> doWriteRegistersNamed(Map<String, byte[]> values) {
		/*
		DbgThread thread = getParentThread().getThread();
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			requestNativeElements().handle(seq::nextIgnore);
		}).then(seq -> {
			thread.listRegisters().handle(seq::next);
		}, TypeSpec.cls(DbgRegisterSet.class)).then((regset, seq) -> {
			Map<String, ?> regs = getCachedAttributes();
			Map<DbgRegister, BigInteger> toWrite = new LinkedHashMap<>();
			for (Map.Entry<String, byte[]> ent : values.entrySet()) {
				String regname = ent.getKey();
				LldbModelTargetRegister reg = (LldbModelTargetRegister) regs.get(regname);
				if (reg == null) {
					throw new DebuggerRegisterAccessException("No such register: " + regname);
				}
				BigInteger val = new BigInteger(1, ent.getValue());
				DbgRegister dbgreg = regset.get(regname);
				toWrite.put(dbgreg, val);
			}
			getParentThread().getThread().writeRegisters(toWrite).handle(seq::next);
			// TODO: Should probably filter only effective and normalized writes in the callback
		}).then(seq -> {
			getListeners().fire.registersUpdated(getProxy(), values);
			seq.exit();
		}).finish();
		*/
		return AsyncUtils.NIL;
	}

	@Override
	public default Map<String, byte[]> getCachedRegisters() {
		return getValues();
	}

	public default Map<String, byte[]> getValues() {
		Map<String, byte[]> result = new HashMap<>();
		for (Entry<String, ?> entry : this.getCachedAttributes().entrySet()) {
			if (entry.getValue() instanceof LldbModelTargetRegister) {
				LldbModelTargetRegister reg = (LldbModelTargetRegister) entry.getValue();
				byte[] bytes = reg.getBytes();
				result.put(entry.getKey(), bytes);
			}
		}
		return result;
	}

}
