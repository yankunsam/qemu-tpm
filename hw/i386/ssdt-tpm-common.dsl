/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Common parts for TPM 1.2 and TPM 2 (with slight differences for PPI)
 * to be #included
 */


    External(\_SB.PCI0.ISA, DeviceObj)
    Scope(\_SB.PCI0.ISA) {
        /* TPM with emulated TPM TIS interface */
        Device (TPM) {
            Name (_HID, EisaID ("PNP0C31"))
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, TPM_TIS_ADDR_BASE, TPM_TIS_ADDR_SIZE)
                IRQNoFlags () {TPM_TIS_IRQ}
            })
            Method (_STA, 0, NotSerialized) {
                Return (0x0F)
            }

            OperationRegion (TTIS, SystemMemory,
                             TPM_TIS_ADDR_BASE, TPM_TIS_ADDR_SIZE)

            // Define TPM Debug register
            Field(TTIS, AnyAcc, NoLock, Preserve) {
                Offset (0xf90),
                TDBG, 32        // QEMU TIS Debug
            }

            // Last accepted opcode
            NAME(OP, Zero)

            // The base address in TIS 'RAM' where we exchange
            // data with the BIOS lies at 0xfed40fa0
            OperationRegion (HIGH, SystemMemory, 0xfed40fa0, TPM_PPI_STRUCT_SIZE)

            // Write given opcode into 'RAM'
            Method (WRAM, 1, Serialized) {
                Field(HIGH, AnyAcc, NoLock, Preserve) {
                   SIG1, 32,
                   SIZE, 16,
                   CODE, 8
                }
                If (LAnd(
                    LEqual(SIG1, TCG_MAGIC),
                    LGreaterEqual(SIZE, 1))
                ) {
                    // Write opcode for BIOS to find
                    Store(Arg0, CODE)
                    // Remember last opcode in CODE
                    Store(Arg0, OP)
                    Return ( 0 )
                }
                Return ( 1 )
            }

            // read data from 'RAM'
            Method (RRAM, 0, Serialized) {
                Name (OPRE, Package(3) { 1, 0, 0})

                Field(HIGH, AnyAcc, NoLock, Preserve) {
                   SIG1, 32,
                   SIZE, 16,
                   CODE, 8,
                   SUCC, 8,
                   CODO, 8,
                   RESP, 32
                }
                // Check signature and sufficient space
                If (LAnd(
                    LEqual(SIG1, TCG_MAGIC),
                    LGreaterEqual(SIZE, 7)
                )) {
                    Store(SUCC, Index(OPRE, 0))
                    Store(CODO, Index(OPRE, 1))
                    Store(RESP, Index(OPRE, 2))
                }
                return (OPRE)
            }

#ifdef TPM_1_2
            // check for supported opcode
            // supported opcodes: 0, 1-11, 14, 21-22
            Method (CKOP, 1, NotSerialized) {
                If (LOr(
                      LOr(
                        LAnd(
                          LGreaterEqual(Arg0, 0),
                          LLessEqual(Arg0, 11)
                        ),
                        LEqual(Arg0, 14)
                      ),
                        LAnd(
                          LGreaterEqual(Arg0, 21),
                          LLessEqual(Arg0, 22)
                        )
                    )) {
                    return (1)
                } else {
                    return (0)
                }
            }
#else
# ifdef TPM_2_0
            // check for supported opcode
            // supported opcodes: 0
            Method (CKOP, 1, NotSerialized) {
                If (LEqual(Arg0, 0)) {
                    return (1)
                } else {
                    return (0)
                }
            }
# endif
#endif

            Method (_DSM, 4, Serialized) {
                If (LEqual (Arg0, ToUUID("3DDDFAA6-361B-4EB4-A424-8D10089D1653"))) {

                    // only supporting API revision 1
                    If (LNotEqual (Arg1, 1)) {
                        Return (Buffer (1) {0})
                    }

                    Store(ToInteger(Arg2), Local0)
                    // standard DSM query function
                    If (LEqual (Local0, 0)) {
                        Return (Buffer () {0xFF, 0x01})
                    }

                    // interface version
                    If (LEqual (Local0, 1)) {
                        Return ("1.2")
                    }

                    // submit TPM operation
                    If (LEqual (Local0, 2)) {
                        // get opcode from package
                        Store(DerefOf(Index(Arg3, 0)), Local0)

                        If (CKOP( Local0 ) ) {
                            // Write the OP into TPM NVRAM
                            Store(WRAM ( Local0 ), Local1)
                            return (Local1)
                        } else {
                            Return (1)
                        }
                    }

                    // get pending TPM operation
                    If (LEqual (Local0, 3)) {
                        NAME(PEOP, Package(2) { 0, 0 })

                        Store ( 0 , Index(PEOP, 0))
                        Store ( OP, Index(PEOP, 1))

                        Return (PEOP)
                    }

                    // action to transition to pre-OS env.
                    If (LEqual (Local0, 4)) {
                        return (2) // Requiring reboot
                    }

                    // get pre-OS TPM operation response
                    If (LEqual (Local0, 5)) {
                        Store (RRAM(), Local0)
                        return ( Local0 )
                    }

                    // preferred user language
                    If (LEqual (Local0, 6)) {
                        return (3) // Not implemented
                    }

                    // submit TPM operation v2
                    If (LEqual (Local0, 7)) {
                        Store(DerefOf(Index(Arg3, 0)), Local0)

                        If (CKOP( Local0 )) {
                            // Write the OP into TPM NVRAM
                            Store(WRAM ( Local0 ), Local1)
                            return (Local1)
                        } else {
                            Return (1)
                        }
                    }

                    // get user confirmation status
                    If (LEqual (Local0, 8)) {
                        Store(DerefOf(Index(Arg3,0)), Local0)

                        if (CKOP( Local0 )) {
                            Return (4)  // allowed, no user required
                        } else {
                            Return (0)  // not implemented
                        }
                    }
                }
                return (Buffer() { 0x0 })
            }
        }
    }
