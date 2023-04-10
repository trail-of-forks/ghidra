package ghidra.app.util.bin.format.dwarf4.next;

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_call_site;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_gnu_call_site;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_label;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_subprogram;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_variable;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import com.google.common.base.Objects;

import ghidra.app.util.bin.format.dwarf4.DIEAggregate;
import ghidra.app.util.bin.format.dwarf4.DWARFLocation;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunctionImporter.DWARFFunction;
import ghidra.app.util.bin.format.dwarf4.next.DWARFVariableVisitor.DWARFVariable;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import java.util.ArrayList;

public class DWARFLocalImporter extends DWARFVariableVisitor {

	private final TaskMonitor monitor;

	public DWARFLocalImporter(DWARFProgram prog, DWARFDataTypeManager dwarfDTM,TaskMonitor monitor) {
		super( prog, prog.getGhidraProgram(), dwarfDTM);
		this.monitor = monitor;
	}

	private void commitLocal(Function func, DWARFVariable dvar) throws InvalidInputException {
		// Attempt to add the variable
		Variable var = buildVariable(dvar);

		// check for an existing local variable with conflict storage.
		boolean hasConflict = false;
		for (Variable existingVar : func.getAllVariables()) {
			if (existingVar.getFirstUseOffset() == var.getFirstUseOffset()
					&& existingVar.getVariableStorage().intersects(var.getVariableStorage())) {
				if ((existingVar instanceof LocalVariable) && Undefined.isUndefined(existingVar.getDataType())) {
					// ignore locals with undefined type - they will be removed below
					continue;
				}
				hasConflict = true;
				break;
			}
		}
		if (hasConflict) {
			appendComment(func.getEntryPoint().add(dvar.lexicalOffset), CodeUnit.EOL_COMMENT,
					"Scope for omitted local variable " + var.toString() + " starts here", "; ");
			return;
		}

		try {
			VariableUtilities.checkVariableConflict(func, null, var.getVariableStorage(), true);
			func.addLocalVariable(var, SourceType.IMPORTED);
		} catch (DuplicateNameException e) {
			int count = 1;
			// Add the variable with an unused name
			String baseName = var.getName();
			while (!monitor.isCancelled()) {
				try {
					var.setName(baseName + "_" + Integer.toString(count), SourceType.IMPORTED);
					func.addLocalVariable(var, SourceType.IMPORTED);
				} catch (DuplicateNameException e1) {
					count++;
					continue;
				}
				break;
			}
		}

	}
	
	public void process()
			throws CancelledException {
		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(prog, "DWARF - Create Funcs & Symbols", monitor)) {
			monitor.checkCanceled();
			try {
				if (diea.getTag() == DWARFTag.DW_TAG_subprogram) {

					try {
						processSubprogram(diea);
					} catch (InvalidInputException e) {
						Msg.error(this, "Failed to process subprog " + diea.getHexOffset(), e);
					}
				}
			} catch (OutOfMemoryError oom) {
				throw oom;
			} catch (Throwable th) {
				Msg.error(this, "Error when processing DWARF information for DIE " + diea.getHexOffset(), th);
				Msg.info(this, "DIE info:\n" + diea.toString());
			}
		}

	}

	private void processSubprogram(DIEAggregate diea) throws InvalidInputException, IOException {
		var dfunc = this.populateDWARFFunc(diea);
		var gfunc = currentProgram.getFunctionManager().getFunctionAt(dfunc.address);
		if (gfunc == null) {
			return;
		}
		
		var vlist = new ArrayList<DWARFVariable>();
		
		for (var child : diea.getChildren(DW_TAG_variable)) {
			var agg  = prog.getAggregate(child);
			var v = this.processVariable(agg, dfunc, null, dfunc.address.getOffset());
			if (v != null) {
				vlist.add(v);
			}
		}
		
		if (!dfunc.localVarErrors) {
			for (var v: vlist) {
				if(v.isStackOffset) {
				commitLocal(gfunc, v);
				}
			}
		}
		
	}

	@Override
	protected Optional<Long> resolveStackOffset(long off, DWARFLocation loc, DWARFFunction dfunc) {
		var func = this.currentProgram.getFunctionManager().getFunctionAt(dfunc.address);
		var live_at = toAddr(loc.getRange().getFrom());
		if (func != null && prog.getRegisterMappings().getGhidraReg( prog.getRegisterMappings().getDWARFStackPointerRegNum()) == currentProgram.getCompilerSpec().getStackPointer()) {
			var cdi = new CallDepthChangeInfo(func);
			var curr_sp_depth = cdi.getSPDepth(live_at);
			if (curr_sp_depth != Function.INVALID_STACK_DEPTH_CHANGE) {
				return Optional.of(off + curr_sp_depth);
			}
		}		
		return Optional.empty();
	}
}
