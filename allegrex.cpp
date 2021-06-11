/*
 *      ALLEGREX processor extension plugin module for the Interactive disassembler (IDA).
 *
 *      updates, fixes and bugreports welcomed (you know where i am)
 *
 *      (w)2006 by Groepaz/Hitmen
 */

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static ea_t ea; // current address within the instruction

//--------------------------------------------------------------------------

enum allegrex_insn_type_t
{
	ALLEGREX_D_UNK_00 = CUSTOM_CMD_ITYPE, 	// 0x70000000
	ALLEGREX_mfic, 				// 0x70000024
	ALLEGREX_mtic, 				// 0x70000026
};

//--------------------------------------------------------------------------
// Analyze an instruction and fill the 'cmd' structure

// Structure for decoded instruction
typedef struct
{
    unsigned long  opcode;  // all bits
    unsigned char  op;      // bits 31-26
    unsigned char  rs;      // bits 25-21
    unsigned char  rt;      // bits 20-16
    unsigned char  rd;      // bits 15-11
    unsigned char  shamt;   // bits 10-6
    unsigned char  funct;   // bits 5-0
    unsigned short imm;     // bits 15-0
    unsigned long  target;  // bits 25-0
    unsigned long  code;    // bits 6-26
} Instr;

void DecodeInst( unsigned long Cmd, Instr * Inst )
{
    Inst->opcode = (unsigned long)    Cmd;
    Inst->op     = (unsigned char)  ( Cmd >> 26 ) & 0x3F;
    Inst->rs     = (unsigned char)  ( Cmd >> 21 ) & 0x1F;
    Inst->rt     = (unsigned char)  ( Cmd >> 16 ) & 0x1F;
    Inst->rd     = (unsigned char)  ( Cmd >> 11 ) & 0x1F;
    Inst->shamt  = (unsigned char)  ( Cmd >>  6 ) & 0x1F;
    Inst->code   = (unsigned long)  ( Cmd >>  6 ) & 0xFFFFF;
    Inst->funct  = (unsigned char)  ( Cmd & 0x0000003F );
    Inst->imm    = (unsigned short) ( Cmd & 0x0000FFFF );
    Inst->target = (unsigned long)  ( Cmd & 0x03FFFFFF );
}

int ana(void)
{
Instr Inst;
unsigned long Cmd;

  Cmd = (unsigned long)(get_byte(cmd.ea+3)<<24)+(get_byte(cmd.ea+2)<<16)+(get_byte(cmd.ea+1)<<8)+get_byte(cmd.ea+0);

  DecodeInst( Cmd, &Inst );

    // unknown opcodes!
    // 880402E8:   00 00 00 70
    if( Inst.opcode == 0x70000000 )
    {
	cmd.itype=ALLEGREX_D_UNK_00;
        return 4;
    }

    if( (Inst.opcode & 0xfc000000) == 0x70000000 )
    {
		// Thanks to TyRaNiD for reversing these two PSP Specifics!
	    switch( Inst.funct )
	    {
		case 0x24:
			cmd.itype=ALLEGREX_mfic;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = Inst.rt;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = Inst.rd;
			return 4;
		break;
		
		case 0x26:
			cmd.itype=ALLEGREX_mtic;
			cmd.Op1.type = o_reg;
			cmd.Op1.reg = Inst.rt;
			cmd.Op2.type = o_reg;
			cmd.Op2.reg = Inst.rd;
			return 4;
		break;
	    }
    }

  return 0;
  
}

//--------------------------------------------------------------------------
// Return the instruction mnemonics

instruc_t Instructions[] = {

 { "halt", 0 },		// 0x70000000
 { "mfic", 0 },		// 0x70000024
 { "mtic", 0 },		// 0x70000026

};

const char *get_insn_mnem(void)
{
	return Instructions[cmd.itype-CUSTOM_CMD_ITYPE].name;
}

//--------------------------------------------------------------------------
// This callback is called for IDP (processor module) notification events
// Here we extend the processor module to disassemble opcode 0xFF
// (This is a hypothetical example)
// There are 2 approaches for the extensions:
//  A. Quick & dirty
//       you implemented custom_ana and custom_out
//       The first checks if the instruction is valid
//       The second generates its text
//  B. Thourough and clean
//       you implement all callbacks
//       custom_ana fills the 'cmd' structure
//       custom_emu creates all xrefs using ua_add_[cd]ref functions
//       custom_out generates the instruction representation
//         (only if the instruction requires special processing
//          or the processor module can't handle the custom instruction for any reason)
//       custom_outop generates the operand representation (only if the operand requires special processing)
//       custom_mnem returns the instruction mnemonics (without the operands)
// The main difference between these 2 approaches is in the presence of cross-references
// and the amount of special processing required by the new instructions

// The quick & dirty approach
// We just produce the instruction mnemonics along with its operands
// No cross-references are created. No special processing.
static int dirty_extension_callback(void * /*user_data*/, int event_id, va_list va)
{
  switch ( event_id )
  {
    case processor_t::custom_ana:
      {
        ea = cmd.ea;
        int length = ana();
        if ( length )
        {
          cmd.size = length;
          return length+1;       // event processed
        }
      }
      break;
    case processor_t::custom_mnem:
      if ( cmd.itype >= CUSTOM_CMD_ITYPE )
      {
        char *buf   = va_arg(va, char *);
        size_t size = va_arg(va, size_t);
        qstrncpy(buf, get_insn_mnem(), size);
        return 2;
      }
      break;
  }
  return 0;                     // event is not processed
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the processor type and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//

static bool hooked = false;
static netnode allegrex_node;
static const char node_name[] = "$ Allegrex processor extender parameters";

int init(void)
{
  if ( ph.id != PLFM_MIPS ) return PLUGIN_SKIP;
  allegrex_node.create(node_name);
  hooked = allegrex_node.altval(0);
  if ( hooked )
  {
    hook_to_notification_point(HT_IDP, dirty_extension_callback, NULL);
    msg("Allegrex processor extender is enabled\n");
    return PLUGIN_KEEP;
  }
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void term(void)
{
  unhook_from_notification_point(HT_IDP, dirty_extension_callback);
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void run(int /*arg*/)
{
  if ( hooked )
    unhook_from_notification_point(HT_IDP, dirty_extension_callback);
  else
    hook_to_notification_point(HT_IDP, dirty_extension_callback, NULL);
  hooked = !hooked;
  allegrex_node.create(node_name);
  allegrex_node.altset(0, hooked);
  info("AUTOHIDE NONE\n"
       "Allegrex processor extender now is %s", hooked ? "enabled" : "disabled");
}

//--------------------------------------------------------------------------
char comment[] = "Allegrex processor extender";

char help[] =
        "Allgrex Processor extension plugin module\n";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Allegrex processor extender";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
