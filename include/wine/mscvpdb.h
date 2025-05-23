/*
 * MS debug information definitions.
 *
 * Copyright (C) 1996 Eric Youngdale
 * Copyright (C) 1999-2000 Ulrich Weigand
 * Copyright (C) 2004 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* MS has stored all its debug information in a set of structures
 * which has been rather consistent across the years (ie you can grasp
 * some continuity, and not so many drastic changes).
 *
 * A bit of history on the various formats
 *      MSVC 1.0        PDB v1 (new format for debug info)
 *      MSVC 2.0        Inclusion in link of debug info (PDB v2)
 *      MSVC 5.0        Types are 24 bits (instead of 16 for <= 4.x)
 *      MSVC x.0        PDB (change in internal streams layout)
 *
 *      .DBG            Contains COFF, FPO and Codeview info
 *      .PDB            New format for debug info (information is
 *                      derived from Codeview information)
 *      VCx0.PDB        x major MSVC number, stores types, while
 *                      <project>.PDB stores symbols.
 *
 * Debug information can either be found in the debug section of a PE
 * module (in something close to a .DBG file), or the debug section
 * can actually refer to an external file, which can be in turn,
 * either a .DBG or .PDB file.
 *
 * Regarding PDB files:
 * -------------------
 * They are implemented as a set of internal streams (as a small file
 * system). The file is split into blocks, an internal stream is made of a set
 * of blocks, that can be non continuous. The table of contents gives the set of
 * blocks for a given stream.
 * Some internal streams are accessed through numbers. For example,
 * #1 is the ROOT (basic information on the file)
 * #2 is the Symbol information (global symbols, local variables...)
 * #3 is the Type internal stream (each the symbols can have type
 * information associated with it).
 *
 * Over the years, three formats existed for the PDB:
 * - ?? was rather linked to 16 bit code (our support shall be rather bad)
 * - JG: it's the signature embedded in the file header. This format has been
 *   used in MSVC 2.0 => 5.0.
 * - DS: it's the signature embedded in the file header. It's the current format
 *   supported my MS.
 *
 * Types internal stream (aka TPI)
 * ---------------------
 * Types (from the Type internal stream) have existed in three flavors (note
 * that those flavors came as historical evolution, but there isn't a one to one
 * link between types evolution and PDB formats' evolutions:
 * - the first flavor (suffixed by V1 in mscvpdb.h), where the types
 *   and subtypes are 16 bit entities; and where strings are in Pascal
 *   format (first char is their length and are not 0 terminated)
 * - the second flavor (suffixed by V2) differs from first flavor with
 *   types and subtypes as 32 bit entities. This forced some
 *   reordering of fields in some types
 * - the third flavor (suffixed by V3) differs from second flavor with
 *   strings stored as C strings (ie are 0 terminated, instead of
 *   length prefixed)
 * The different flavors can coexist in the same file (is this really
 * true ??)
 *
 * For the evolution of types, the need of the second flavor was the
 * number of types to be defined (limited to 0xFFFF, including the C
 * basic types); the need of the third flavor is the increase of
 * symbol size (to be greater than 256), which was likely needed for
 * complex C++ types (nested + templates).
 *
 * It's not possible to represent some disk layout with C structures
 * as there are several contiguous entries of variable length.
 * Of example of them is called 'numeric leaf' and represent several
 * leaf values (integers, reals...).
 * All of these contiguous values are packed in a flexible array member.
 *
 * Symbols internal stream
 * -----------------------
 * Here also we find three flavors (that we've suffixed with _V1, _V2
 * and _V3) even if their evolution is closer to the evolution of
 * types, they are not completely linked together.
 */

#pragma pack(push,1)

/* ======================================== *
 *             Internal types
 * ======================================== */

/* First versions (v1, v2) of CV data is stored as Pascal strings.
 * Third version uses C string instead.
 */
struct p_string
{
    unsigned char               namelen;
    char                        name[];
};

typedef unsigned short  cv_typ16_t;
typedef unsigned int    cv_typ_t;
typedef cv_typ_t        cv_itemid_t;

typedef struct cv_property_t
{
    unsigned short  is_packed               : 1;
    unsigned short  has_ctor                : 1;
    unsigned short  has_overloaded_operator : 1;
    unsigned short  is_nested               : 1;
    unsigned short  has_nested              : 1;
    unsigned short  has_overloaded_assign   : 1;
    unsigned short  has_operator_cast       : 1;
    unsigned short  is_forward_defn         : 1;
    unsigned short  is_scoped               : 1;
    unsigned short  has_decorated_name      : 1; /* follows name field */
    unsigned short  is_sealed               : 1; /* not usage as base class */
    unsigned short  hfa                     : 2;
    unsigned short  is_intrinsic            : 1;
    unsigned short  mocom                   : 2;
}
cv_property_t;

/* ======================================== *
 *             Type information
 * ======================================== */

union codeview_type
{
    struct
    {
        unsigned short int      len;
        unsigned short int      id;
    } generic;

    /* types found in TPI stream (#2) */
    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               attribute;
        cv_typ16_t              type;
    } modifier_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        short int               attribute;
    } modifier_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               attribute;
        short int               datatype;
        struct p_string         p_name;
    } pointer_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                datatype;
        unsigned int            attribute;
        struct p_string         p_name;
    } pointer_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ16_t              elemtype;
        cv_typ16_t              idxtype;
        unsigned char           data[];
        /* <numeric leaf>       arrlen; */
        /* struct p_string      p_name; */
    } array_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                elemtype;
        cv_typ_t                idxtype;
        unsigned char           data[];
        /* <numeric leaf>       arrlen; */
        /* struct p_string      p_name; */
    } array_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                elemtype;
        cv_typ_t                idxtype;
        unsigned char           data[];
        /* <numeric leaf>       arrlen; */
        /* char                 name[]; */
    } array_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               n_element;
        cv_typ16_t              fieldlist;
        cv_property_t           property;
        cv_typ16_t              derived;
        cv_typ16_t              vshape;
        unsigned char           data[];
        /* <numeric leaf>       structlen; */
        /* struct p_string      p_name; */
    } struct_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               n_element;
        cv_property_t           property;
        cv_typ_t                fieldlist;
        cv_typ_t                derived;
        cv_typ_t                vshape;
        unsigned char           data[];
        /* <numeric leaf>       structlen; */
        /* struct p_string      p_name; */
    } struct_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               n_element;
        cv_property_t           property;
        cv_typ_t                fieldlist;
        cv_typ_t                derived;
        cv_typ_t                vshape;
        unsigned char           data[];
        /* <numeric leaf>       structlen; */
        /* char                 name[]; */
    } struct_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               count;
        cv_typ16_t              fieldlist;
        cv_property_t           property;
        unsigned char           data[];
        /* <numeric leaf>       unionlen; */
        /* struct p_string      p_name; */
    } union_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               count;
        cv_property_t           property;
        cv_typ_t                fieldlist;
        unsigned char           data[];
        /* <numeric leaf>       unionlen; */
        /* struct p_string      p_name; */
    } union_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               count;
        cv_property_t           property;
        cv_typ_t                fieldlist;
        unsigned char           data[];
        /* <numeric leaf>       unionlen; */
        /* char                 name[]; */
    } union_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               count;
        cv_typ16_t              type;
        cv_typ16_t              fieldlist;
        cv_property_t           property;
        struct p_string         p_name;
    } enumeration_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               count;
        cv_property_t           property;
        cv_typ_t                type;
        cv_typ_t                fieldlist;
        struct p_string         p_name;
    } enumeration_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        short int               count;
        cv_property_t           property;
        cv_typ_t                type;
        cv_typ_t                fieldlist;
        char                    name[];
    } enumeration_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ16_t              rvtype;
        unsigned char           callconv;
        unsigned char           funcattr;
        unsigned short int      params;
        cv_typ16_t              arglist;
    } procedure_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                rvtype;
        unsigned char           callconv;
        unsigned char           funcattr;
        unsigned short int      params;
        cv_typ_t                arglist;
    } procedure_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ16_t              rvtype;
        cv_typ16_t              class_type;
        cv_typ16_t              this_type;
        unsigned char           callconv;
        unsigned char           funcattr;
        unsigned short int      params;
        cv_typ16_t              arglist;
        unsigned int            this_adjust;
    } mfunction_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                rvtype;
        cv_typ_t                class_type;
        cv_typ_t                this_type;
        unsigned char           callconv;
        unsigned char           funcattr;
        unsigned short          params;
        cv_typ_t                arglist;
        unsigned int            this_adjust;
    } mfunction_v2;

    /* types found in IPI stream (#4) */
    struct
    {
        unsigned short int      len;
        unsigned short int      id; /* LF_FUNC_ID */
        cv_itemid_t             scopeId;
        cv_typ_t                type;
        char                    name[];
    } func_id_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id; /* LF_MFUNC_ID */
        cv_typ_t                parentType;
        cv_typ_t                type;
        char                    name[];
    } mfunc_id_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id; /* LF_STRING_ID */
        cv_itemid_t             strid;
        char                    name[];
    } string_id_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id; /* LF_UDT_SRC_LINE */
        cv_typ_t                type;
        cv_itemid_t             src;
        unsigned int            line;
    } udt_src_line_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id; /*  LF_UDT_MOD_SRC_LINE */
        cv_typ_t                type;
        cv_itemid_t             src;
        unsigned int            line;
        unsigned short          imod;
    } udt_mod_src_line_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id; /*  LF_BUILDINFO */
        unsigned short          count;
        cv_itemid_t             arg[];
    } buildinfo_v3;

};

union codeview_reftype
{
    struct
    {
        unsigned short int      len;
        unsigned short int      id;
    } generic;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned char           list[];
    } fieldlist;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned char           nbits;
        unsigned char           bitoff;
        cv_typ16_t              type;
    } bitfield_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        unsigned char           nbits;
        unsigned char           bitoff;
    } bitfield_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned short          num;
        cv_typ16_t              args[];
    } arglist_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned                num;
        cv_typ_t                args[];
    } arglist_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned short          num;
        cv_typ16_t              drvdcls[];
    } derived_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned                num;
        cv_typ_t                drvdcls[];
    } derived_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        cv_typ_t                baseVftable;
        unsigned                offsetInObjectLayout;
        unsigned                cbstr;
        char                    names[]; /* array of len 0-terminated strings (size of cbstr in char:s) */
    } vftable_v3;
};

union codeview_fieldtype
{
    struct
    {
        unsigned short int      id;
    } generic;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		type;
        short int		attribute;
        unsigned char           data[];
        /* <numeric leaf>       offset; */
    } bclass_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        unsigned char           data[];
        /* <numeric leaf>       offset; */
    } bclass_v2;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		btype;
        cv_typ16_t		vbtype;
        short int		attribute;
        unsigned char           data[];
        /* <numeric leaf>       vbpoff; */
        /* <numeric leaf>       vboff; */
    } vbclass_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        btype;
        cv_typ_t	        vbtype;
        unsigned char           data[];
        /* <numeric leaf>       vbpoff; */
        /* <numeric leaf>       vboff; */
    } vbclass_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        unsigned char           data[];
        /* <numeric leaf>       value; */
        /* struct p_string      p_name; */
    } enumerate_v1;

   struct
    {
        unsigned short int      id;
        short int               attribute;
        unsigned char           data[];
        /* <numeric leaf>       value; */
        /* char                 name[]; */
    } enumerate_v3;

    struct
    {
        unsigned short int      id;
        cv_typ16_t	        type;
        struct p_string         p_name;
    } friendfcn_v1;

    struct
    {
        unsigned short int      id;
        short int		_pad0;
        cv_typ_t	        type;
        struct p_string         p_name;
    } friendfcn_v2;

    struct
    {
        unsigned short int      id;
        short int               _pad0;
        cv_typ_t                type;
        char                    name[];
    } friendfcn_v3;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		type;
        short int		attribute;
        unsigned char           data[];
        /* <numeric leaf>       offset; */
        /* struct p_string      p_name; */
    } member_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        unsigned char           data[];
        /* <numeric leaf>       offset; */
        /* struct p_string      p_name; */
    } member_v2;

    struct
    {
        unsigned short int      id;
        short int               attribute;
        cv_typ_t                type;
        unsigned char           data[];
        /* <numeric leaf>       offset; */
        /* char                 name[]; */
    }
    member_v3;

    struct
    {
        unsigned short int      id;
        cv_typ16_t              type;
        short int		attribute;
        struct p_string         p_name;
    } stmember_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        struct p_string         p_name;
    } stmember_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        char                    name[];
    } stmember_v3;

    struct
    {
        unsigned short int      id;
        short int		count;
        cv_typ16_t		mlist;
        struct p_string         p_name;
    } method_v1;

    struct
    {
        unsigned short int      id;
        short int		count;
        cv_typ_t	        mlist;
        struct p_string         p_name;
    } method_v2;

    struct
    {
        unsigned short int      id;
        short int		count;
        cv_typ_t	        mlist;
        char                    name[];
    } method_v3;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		type;
        struct p_string         p_name;
    } nesttype_v1;

    struct
    {
        unsigned short int      id;
        short int		_pad0;
        cv_typ_t	        type;
        struct p_string         p_name;
    } nesttype_v2;

    struct
    {
        unsigned short int      id;
        short int		_pad0;
        cv_typ_t	        type;
        char                    name[];
    } nesttype_v3;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		type;
    } vfunctab_v1;

    struct
    {
        unsigned short int      id;
        short int		_pad0;
        cv_typ_t	        type;
    } vfunctab_v2;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		type;
    } friendcls_v1;

    struct
    {
        unsigned short int      id;
        short int		_pad0;
        cv_typ_t	        type;
    } friendcls_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ16_t		type;
        struct p_string         p_name;
    } onemethod_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t 	        type;
        struct p_string         p_name;
    } onemethod_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t 	        type;
        char                    name[];
    } onemethod_v3;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ16_t		type;
        unsigned int	        vtab_offset;
        struct p_string         p_name;
    } onemethod_virt_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        unsigned int	        vtab_offset;
        struct p_string         p_name;
    } onemethod_virt_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        unsigned int	        vtab_offset;
        char                    name[];
    } onemethod_virt_v3;

    struct
    {
        unsigned short int      id;
        cv_typ16_t		type;
        unsigned int	        offset;
    } vfuncoff_v1;

    struct
    {
        unsigned short int      id;
        short int		_pad0;
        cv_typ_t	        type;
        unsigned int	        offset;
    } vfuncoff_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ16_t		type;
        struct p_string         p_name;
    } nesttypeex_v1;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        struct p_string         p_name;
    } nesttypeex_v2;

    struct
    {
        unsigned short int      id;
        short int		attribute;
        cv_typ_t	        type;
        struct p_string         p_name;
    } membermodify_v2;

    struct
    {
        unsigned short int      id;
        cv_typ16_t              ref;
    } index_v1;

    struct
    {
        unsigned short int      id;
        short int               _pad0;
        cv_typ_t                ref;
    } index_v2;
};


/*
 * This covers the basic datatypes that VC++ seems to be using these days.
 * 32 bit mode only.  There are additional numbers for the pointers in 16
 * bit mode.  There are many other types listed in the documents, but these
 * are apparently not used by the compiler, or represent pointer types
 * that are not used.
 *
 * Official MS documentation says that type (< 0x4000, so 12 bits) is made of:
 *        +----------+------+------+----------+------+
 *        |    11    | 10-8 | 7-4  |     3    | 2-0  |
 *        +----------+------+------+----------+------+
 *        | reserved | mode | type | reserved | size |
 *        +----------+------+------+----------+------+
 * In recent PDB files, type 8 exists, and is seen as an HRESULT... So we've
 * added this basic type... as if bit 3 had been integrated into the size field
 */

/* the type number of a built-in type is a 16-bit value specified in the following format:
    bit #   |   11     |   10-8   |   7-4    |    3     |    2-0   |
    field   | reserved |   mode   |   type   | reserved |   size   |

    where
        <type> is one of the following types:
                0x00 Special
                0x01 Signed integral value
                0x02 Unsigned integral value
                0x03 Boolean
                0x04 Real
                0x05 Complex
                0x06 Special2
                0x07 Real int value
                0x08 Reserved
                0x09 Reserved
                0x0a Reserved
                0x0b Reserved
                0x0c Reserved
                0x0d Reserved
                0x0e Reserved
                0x0f Reserved for debugger expression evaluator

        <size> is an enumerated value for each of the types.
                Type = special
                    0x00 No type
                    0x01 Absolute symbol
                    0x02 Segment
                    0x03 Void
                    0x04 Basic 8-byte currency value
                    0x05 Near Basic string
                    0x06 Far Basic string
                    0x07 Untranslated type from previous Microsoft symbol formats
                Type = signed/unsigned integral and Boolean values
                    0x00 1 byte
                    0x01 2 byte
                    0x02 4 byte
                    0x03 8 byte
                    0x04 Reserved
                    0x05 Reserved
                    0x06 Reserved
                    0x07 Reserved
                Type = real and complex
                    0x00 32 bit
                    0x01 64 bit
                    0x02 80 bit
                    0x03 128 bit
                    0x04 48 bit
                    0x05 Reserved
                    0x06 Reserved
                    0x07 Reserved
                Type = special2
                    0x00 Bit
                    0x01 Pascal CHAR
                Type = Real int
                    0x00 Char
                    0x01 Wide character
                    0x02 2-byte signed integer
                    0x03 2-byte unsigned integer
                    0x04 4-byte signed integer
                    0x05 4-byte unsigned integer
                    0x06 8-byte signed integer
                    0x07 8-byte unsigned integer

            <mode> is the pointer mode:
                0x00 Direct; not a pointer
                0x01 Near pointer
                0x02 Far pointer
                0x03 Huge pointer
                0x04 32-bit near pointer
                0x05 32-bit far pointer
                0x06 64-bit near pointer
                0x07 Reserved
*/

/* basic types */
#define T_NOTYPE            0x0000  /* Notype */
#define T_ABS               0x0001  /* Abs */
#define T_SEGMENT           0x0002  /* segment type */
#define T_VOID              0x0003  /* Void */
#define T_CURRENCY          0x0004  /* basic 8-byte currency value */
#define T_NBASICSTR         0x0005  /* near basic string */
#define T_FBASICSTR         0x0006  /* far basic string */
#define T_NOTTRANS          0x0007  /* untranslated type record from MS symbol format */
#define T_HRESULT           0x0008  /* HRESULT - or error code ??? */
#define T_CHAR              0x0010  /* signed char */
#define T_SHORT             0x0011  /* short */
#define T_LONG              0x0012  /* long */
#define T_QUAD              0x0013  /* long long */
#define T_OCT               0x0014  /* 128bit int */
#define T_UCHAR             0x0020  /* unsigned  char */
#define T_USHORT            0x0021  /* unsigned short */
#define T_ULONG             0x0022  /* unsigned long */
#define T_UQUAD             0x0023  /* unsigned long long */
#define T_UOCT              0x0024  /* 128bit unsigned int */
#define T_BOOL08            0x0030  /* 8-bit boolean */
#define T_BOOL16            0x0031  /* 16-bit boolean */
#define T_BOOL32            0x0032  /* 32-bit boolean */
#define T_BOOL64            0x0033  /* 64-bit boolean */
#define T_REAL32            0x0040  /* float */
#define T_REAL64            0x0041  /* double */
#define T_REAL80            0x0042  /* 80-bit real */
#define T_REAL128           0x0043  /* 128-bit real */
#define T_REAL48            0x0044  /* 48-bit real */
#define T_REAL16            0x0046  /* 16-bit real */
#define T_CPLX32            0x0050  /* 32-bit complex number */
#define T_CPLX64            0x0051  /* 64-bit complex number */
#define T_CPLX80            0x0052  /* 80-bit complex number */
#define T_CPLX128           0x0053  /* 128-bit complex number */
#define T_BIT               0x0060  /* bit */
#define T_PASCHAR           0x0061  /* pascal CHAR */
#define T_RCHAR             0x0070  /* real char */
#define T_WCHAR             0x0071  /* wide char */
#define T_INT2              0x0072  /* real 16-bit signed int */
#define T_UINT2             0x0073  /* real 16-bit unsigned int */
#define T_INT4              0x0074  /* int */
#define T_UINT4             0x0075  /* unsigned int */
#define T_INT8              0x0076  /* 64-bit signed int */
#define T_UINT8             0x0077  /* 64-bit unsigned int */
#define T_CHAR16            0x007a  /* 16-bit unicode char */
#define T_CHAR32            0x007b  /* 32-bit unicode char */
#define T_CHAR8             0x007c  /* 8-bit unicode char (C++ 20) */

/* near pointers to basic types */
#define T_PVOID             0x0103  /* near pointer to void */
#define T_PCURRENCY         0x0104  /* near pointer to currency */
#define T_PCHAR             0x0110  /* Near pointer to 8-bit signed */
#define T_PSHORT            0x0111  /* Near pointer to 16-bit signed */
#define T_PLONG             0x0112  /* Near pointer to 32-bit signed */
#define T_PQUAD             0x0113  /* Near pointer to 64-bit signed */
#define T_POCT              0x0114  /* Near pointer to 128-bit signed */
#define T_PUCHAR            0x0120  /* Near pointer to 8-bit unsigned */
#define T_PUSHORT           0x0121  /* Near pointer to 16-bit unsigned */
#define T_PULONG            0x0122  /* Near pointer to 32-bit unsigned */
#define T_PUQUAD            0x0123  /* Near pointer to 64-bit unsigned */
#define T_PUOCT             0x0124  /* Near pointer to 128-bit unsigned */
#define T_PBOOL08           0x0130  /* Near pointer to 8-bit Boolean */
#define T_PBOOL16           0x0131  /* Near pointer to 16-bit Boolean */
#define T_PBOOL32           0x0132  /* Near pointer to 32-bit Boolean */
#define T_PBOOL64           0x0133  /* Near pointer to 64-bit Boolean */
#define T_PREAL32           0x0140  /* Near pointer to 32-bit real */
#define T_PREAL64           0x0141  /* Near pointer to 64-bit real */
#define T_PREAL80           0x0142  /* Near pointer to 80-bit real */
#define T_PREAL128          0x0143  /* Near pointer to 128-bit real */
#define T_PREAL48           0x0144  /* Near pointer to 48-bit real */
#define T_PREAL16           0x0146  /* Near pointer to 16-bit real */
#define T_PCPLX32           0x0150  /* Near pointer to 32-bit complex */
#define T_PCPLX64           0x0151  /* Near pointer to 64-bit complex */
#define T_PCPLX80           0x0152  /* Near pointer to 80-bit complex */
#define T_PCPLX128          0x0153  /* Near pointer to 128-bit complex */
#define T_PRCHAR            0x0170  /* Near pointer to a real char */
#define T_PWCHAR            0x0171  /* Near pointer to a wide char */
#define T_PINT2             0x0172  /* Near pointer to 16-bit signed int */
#define T_PUINT2            0x0173  /* Near pointer to 16-bit unsigned int */
#define T_PINT4             0x0174  /* Near pointer to 32-bit signed int */
#define T_PUINT4            0x0175  /* Near pointer to 32-bit unsigned int */
#define T_PINT8             0x0176  /* Near pointer to 64-bit signed int */
#define T_PUINT8            0x0177  /* Near pointer to 64-bit unsigned int */
#define T_PCHAR16           0x017a  /* Near pointer to 16-bit unicode char */
#define T_PCHAR32           0x017b  /* Near pointer to 32-bit unicode char */
#define T_PCHAR8            0x017c  /* Near pointer to 8-bit unicode char */

/* far pointers to basic types */
#define T_PFVOID            0x0203  /* Far pointer to void */
#define T_PFCURRENCT        0x0204  /* Far pointer to currency */
#define T_PFCHAR            0x0210  /* Far pointer to 8-bit signed */
#define T_PFSHORT           0x0211  /* Far pointer to 16-bit signed */
#define T_PFLONG            0x0212  /* Far pointer to 32-bit signed */
#define T_PFQUAD            0x0213  /* Far pointer to 64-bit signed */
#define T_PFOCT             0x0214  /* Far pointer to 128-bit signed */
#define T_PFUCHAR           0x0220  /* Far pointer to 8-bit unsigned */
#define T_PFUSHORT          0x0221  /* Far pointer to 16-bit unsigned */
#define T_PFULONG           0x0222  /* Far pointer to 32-bit unsigned */
#define T_PFUQUAD           0x0223  /* Far pointer to 64-bit unsigned */
#define T_PFUOCT            0x0224  /* Far pointer to 128-bit unsigned */
#define T_PFBOOL08          0x0230  /* Far pointer to 8-bit Boolean */
#define T_PFBOOL16          0x0231  /* Far pointer to 16-bit Boolean */
#define T_PFBOOL32          0x0232  /* Far pointer to 32-bit Boolean */
#define T_PFBOOL64          0x0233  /* Far pointer to 64-bit Boolean */
#define T_PFREAL32          0x0240  /* Far pointer to 32-bit real */
#define T_PFREAL64          0x0241  /* Far pointer to 64-bit real */
#define T_PFREAL80          0x0242  /* Far pointer to 80-bit real */
#define T_PFREAL128         0x0243  /* Far pointer to 128-bit real */
#define T_PFREAL48          0x0244  /* Far pointer to 48-bit real */
#define T_PFREAL16          0x0246  /* Far pointer to 16-bit real */
#define T_PFCPLX32          0x0250  /* Far pointer to 32-bit complex */
#define T_PFCPLX64          0x0251  /* Far pointer to 64-bit complex */
#define T_PFCPLX80          0x0252  /* Far pointer to 80-bit complex */
#define T_PFCPLX128         0x0253  /* Far pointer to 128-bit complex */
#define T_PFRCHAR           0x0270  /* Far pointer to a real char */
#define T_PFWCHAR           0x0271  /* Far pointer to a wide char */
#define T_PFINT2            0x0272  /* Far pointer to 16-bit signed int */
#define T_PFUINT2           0x0273  /* Far pointer to 16-bit unsigned int */
#define T_PFINT4            0x0274  /* Far pointer to 32-bit signed int */
#define T_PFUINT4           0x0275  /* Far pointer to 32-bit unsigned int */
#define T_PFINT8            0x0276  /* Far pointer to 64-bit signed int */
#define T_PFUINT8           0x0277  /* Far pointer to 64-bit unsigned int */
#define T_PFCHAR16          0x027a  /* Far pointer to 16-bit unicode char */
#define T_PFCHAR32          0x027b  /* Far pointer to 32-bit unicode char */
#define T_PFCHAR8           0x027c  /* Far pointer to 8-bit unicode char */

/* huge pointers to basic types */
#define T_PHVOID            0x0303  /* Huge pointer to void */
#define T_PHCURRENCY        0x0304  /* Huge pointer to currency */
#define T_PHCHAR            0x0310  /* Huge pointer to 8-bit signed */
#define T_PHSHORT           0x0311  /* Huge pointer to 16-bit signed */
#define T_PHLONG            0x0312  /* Huge pointer to 32-bit signed */
#define T_PHQUAD            0x0313  /* Huge pointer to 64-bit signed */
#define T_PHOCT             0x0314  /* Huge pointer to 128-bit signed */
#define T_PHUCHAR           0x0320  /* Huge pointer to 8-bit unsigned */
#define T_PHUSHORT          0x0321  /* Huge pointer to 16-bit unsigned */
#define T_PHULONG           0x0322  /* Huge pointer to 32-bit unsigned */
#define T_PHUQUAD           0x0323  /* Huge pointer to 64-bit unsigned */
#define T_PHUOCT            0x0324  /* Huge pointer to 128-bit unsigned */
#define T_PHBOOL08          0x0330  /* Huge pointer to 8-bit Boolean */
#define T_PHBOOL16          0x0331  /* Huge pointer to 16-bit Boolean */
#define T_PHBOOL32          0x0332  /* Huge pointer to 32-bit Boolean */
#define T_PHBOOL64          0x0333  /* Huge pointer to 64-bit Boolean */
#define T_PHREAL32          0x0340  /* Huge pointer to 32-bit real */
#define T_PHREAL64          0x0341  /* Huge pointer to 64-bit real */
#define T_PHREAL80          0x0342  /* Huge pointer to 80-bit real */
#define T_PHREAL128         0x0343  /* Huge pointer to 128-bit real */
#define T_PHREAL48          0x0344  /* Huge pointer to 48-bit real */
#define T_PHREAL16          0x0346  /* Far pointer to 16-bit real */
#define T_PHCPLX32          0x0350  /* Huge pointer to 32-bit complex */
#define T_PHCPLX64          0x0351  /* Huge pointer to 64-bit complex */
#define T_PHCPLX80          0x0352  /* Huge pointer to 80-bit complex */
#define T_PHCPLX128         0x0353  /* Huge pointer to 128-bit real */
#define T_PHRCHAR           0x0370  /* Huge pointer to a real char */
#define T_PHWCHAR           0x0371  /* Huge pointer to a wide char */
#define T_PHINT2            0x0372  /* Huge pointer to 16-bit signed int */
#define T_PHUINT2           0x0373  /* Huge pointer to 16-bit unsigned int */
#define T_PHINT4            0x0374  /* Huge pointer to 32-bit signed int */
#define T_PHUINT4           0x0375  /* Huge pointer to 32-bit unsigned int */
#define T_PHINT8            0x0376  /* Huge pointer to 64-bit signed int */
#define T_PHUINT8           0x0377  /* Huge pointer to 64-bit unsigned int */
#define T_PHCHAR16          0x037a  /* Huge pointer to 16-bit unicode char */
#define T_PHCHAR32          0x037b  /* Huge pointer to 32-bit unicode char */
#define T_PHCHAR8           0x037c  /* Huge pointer to 8-bit unicode char */

/* 32-bit near pointers to basic types */
#define T_32PVOID           0x0403  /* 32-bit near pointer to void */
#define T_32PCURRENCY       0x0404  /* 32-bit near pointer to currency */
#define T_32PHRESULT        0x0408  /* 16:32 near pointer to HRESULT - or error code ??? */
#define T_32PCHAR           0x0410  /* 16:32 near pointer to 8-bit signed */
#define T_32PSHORT          0x0411  /* 16:32 near pointer to 16-bit signed */
#define T_32PLONG           0x0412  /* 16:32 near pointer to 32-bit signed */
#define T_32PQUAD           0x0413  /* 16:32 near pointer to 64-bit signed */
#define T_32POCT            0x0414  /* 16:32 near pointer to 128-bit signed */
#define T_32PUCHAR          0x0420  /* 16:32 near pointer to 8-bit unsigned */
#define T_32PUSHORT         0x0421  /* 16:32 near pointer to 16-bit unsigned */
#define T_32PULONG          0x0422  /* 16:32 near pointer to 32-bit unsigned */
#define T_32PUQUAD          0x0423  /* 16:32 near pointer to 64-bit unsigned */
#define T_32PUOCT           0x0424  /* 16:32 near pointer to 128-bit unsigned */
#define T_32PBOOL08         0x0430  /* 16:32 near pointer to 8-bit Boolean */
#define T_32PBOOL16         0x0431  /* 16:32 near pointer to 16-bit Boolean */
#define T_32PBOOL32         0x0432  /* 16:32 near pointer to 32-bit Boolean */
#define T_32PBOOL64         0x0433  /* 16:32 near pointer to 64-bit Boolean */
#define T_32PREAL32         0x0440  /* 16:32 near pointer to 32-bit real */
#define T_32PREAL64         0x0441  /* 16:32 near pointer to 64-bit real */
#define T_32PREAL80         0x0442  /* 16:32 near pointer to 80-bit real */
#define T_32PREAL128        0x0443  /* 16:32 near pointer to 128-bit real */
#define T_32PREAL48         0x0444  /* 16:32 near pointer to 48-bit real */
#define T_32PREAL16         0x0446  /* 16:32 near pointer to 16-bit real */
#define T_32PCPLX32         0x0450  /* 16:32 near pointer to 32-bit complex */
#define T_32PCPLX64         0x0451  /* 16:32 near pointer to 64-bit complex */
#define T_32PCPLX80         0x0452  /* 16:32 near pointer to 80-bit complex */
#define T_32PCPLX128        0x0453  /* 16:32 near pointer to 128-bit complex */
#define T_32PRCHAR          0x0470  /* 16:32 near pointer to a real char */
#define T_32PWCHAR          0x0471  /* 16:32 near pointer to a wide char */
#define T_32PINT2           0x0472  /* 16:32 near pointer to 16-bit signed int */
#define T_32PUINT2          0x0473  /* 16:32 near pointer to 16-bit unsigned int */
#define T_32PINT4           0x0474  /* 16:32 near pointer to 32-bit signed int */
#define T_32PUINT4          0x0475  /* 16:32 near pointer to 32-bit unsigned int */
#define T_32PINT8           0x0476  /* 16:32 near pointer to 64-bit signed int */
#define T_32PUINT8          0x0477  /* 16:32 near pointer to 64-bit unsigned int */
#define T_32PCHAR16         0x047a  /* 16:32 near pointer to 16-bit unicode char */
#define T_32PCHAR32         0x047b  /* 16:32 near pointer to 32-bit unicode char */
#define T_32PCHAR8          0x047c  /* 16:32 near pointer to 8-bit unicode char */

/* 32-bit far pointers to basic types */
#define T_32PFVOID          0x0503  /* 32-bit far pointer to void */
#define T_32PFCURRENCY      0x0504  /* 32-bit far pointer to void */
#define T_32PFHRESULT       0x0508  /* 16:32 far pointer to HRESULT - or error code ??? */
#define T_32PFCHAR          0x0510  /* 16:32 far pointer to 8-bit signed */
#define T_32PFSHORT         0x0511  /* 16:32 far pointer to 16-bit signed */
#define T_32PFLONG          0x0512  /* 16:32 far pointer to 32-bit signed */
#define T_32PFQUAD          0x0513  /* 16:32 far pointer to 64-bit signed */
#define T_32PFOCT           0x0514  /* 16:32 far pointer to 128-bit signed */
#define T_32PFUCHAR         0x0520  /* 16:32 far pointer to 8-bit unsigned */
#define T_32PFUSHORT        0x0521  /* 16:32 far pointer to 16-bit unsigned */
#define T_32PFULONG         0x0522  /* 16:32 far pointer to 32-bit unsigned */
#define T_32PFUQUAD         0x0523  /* 16:32 far pointer to 64-bit unsigned */
#define T_32PFUOCT          0x0524  /* 16:32 far pointer to 128-bit unsigned */
#define T_32PFBOOL08        0x0530  /* 16:32 far pointer to 8-bit Boolean */
#define T_32PFBOOL16        0x0531  /* 16:32 far pointer to 16-bit Boolean */
#define T_32PFBOOL32        0x0532  /* 16:32 far pointer to 32-bit Boolean */
#define T_32PFBOOL64        0x0533  /* 16:32 far pointer to 64-bit Boolean */
#define T_32PFREAL32        0x0540  /* 16:32 far pointer to 32-bit real */
#define T_32PFREAL64        0x0541  /* 16:32 far pointer to 64-bit real */
#define T_32PFREAL80        0x0542  /* 16:32 far pointer to 80-bit real */
#define T_32PFREAL128       0x0543  /* 16:32 far pointer to 128-bit real */
#define T_32PFREAL48        0x0544  /* 16:32 far pointer to 48-bit real */
#define T_32PFREAL16        0x0546  /* 16:32 far pointer to 16-bit real */
#define T_32PFCPLX32        0x0550  /* 16:32 far pointer to 32-bit complex */
#define T_32PFCPLX64        0x0551  /* 16:32 far pointer to 64-bit complex */
#define T_32PFCPLX80        0x0552  /* 16:32 far pointer to 80-bit complex */
#define T_32PFCPLX128       0x0553  /* 16:32 far pointer to 128-bit complex */
#define T_32PFRCHAR         0x0570  /* 16:32 far pointer to a real char */
#define T_32PFWCHAR         0x0571  /* 16:32 far pointer to a wide char */
#define T_32PFINT2          0x0572  /* 16:32 far pointer to 16-bit signed int */
#define T_32PFUINT2         0x0573  /* 16:32 far pointer to 16-bit unsigned int */
#define T_32PFINT4          0x0574  /* 16:32 far pointer to 32-bit signed int */
#define T_32PFUINT4         0x0575  /* 16:32 far pointer to 32-bit unsigned int */
#define T_32PFINT8          0x0576  /* 16:32 far pointer to 64-bit signed int */
#define T_32PFUINT8         0x0577  /* 16:32 far pointer to 64-bit unsigned int */
#define T_32PFCHAR16        0x057a  /* 16:32 far pointer to 16-bit unicode char */
#define T_32PFCHAR32        0x057b  /* 16:32 far pointer to 32-bit unicode char */
#define T_32PFCHAR8         0x057c  /* 16:32 far pointer to 8-bit unicode char */

/* 64-bit near pointers to basic types */
#define T_64PVOID           0x0603  /* 64-bit near pointer to void */
#define T_64PCURRENCY       0x0604  /* 64-bit near pointer to void */
#define T_64PHRESULT        0x0608  /* 64 near pointer to HRESULT - or error code ??? */
#define T_64PCHAR           0x0610  /* 64 near pointer to 8-bit signed */
#define T_64PSHORT          0x0611  /* 64 near pointer to 16-bit signed */
#define T_64PLONG           0x0612  /* 64 near pointer to 32-bit signed */
#define T_64PQUAD           0x0613  /* 64 near pointer to 64-bit signed */
#define T_64POCT            0x0614  /* 64 near pointer to 128-bit signed */
#define T_64PUCHAR          0x0620  /* 64 near pointer to 8-bit unsigned */
#define T_64PUSHORT         0x0621  /* 64 near pointer to 16-bit unsigned */
#define T_64PULONG          0x0622  /* 64 near pointer to 32-bit unsigned */
#define T_64PUQUAD          0x0623  /* 64 near pointer to 64-bit unsigned */
#define T_64PUOCT           0x0624  /* 64 near pointer to 128-bit unsigned */
#define T_64PBOOL08         0x0630  /* 64 near pointer to 8-bit Boolean */
#define T_64PBOOL16         0x0631  /* 64 near pointer to 16-bit Boolean */
#define T_64PBOOL32         0x0632  /* 64 near pointer to 32-bit Boolean */
#define T_64PBOOL64         0x0633  /* 64 near pointer to 64-bit Boolean */
#define T_64PREAL32         0x0640  /* 64 near pointer to 32-bit real */
#define T_64PREAL64         0x0641  /* 64 near pointer to 64-bit real */
#define T_64PREAL80         0x0642  /* 64 near pointer to 80-bit real */
#define T_64PREAL128        0x0643  /* 64 near pointer to 128-bit real */
#define T_64PREAL48         0x0644  /* 64 near pointer to 48-bit real */
#define T_64PREAL16         0x0646  /* 64 near pointer to 16-bit real */
#define T_64PCPLX32         0x0650  /* 64 near pointer to 32-bit complex */
#define T_64PCPLX64         0x0651  /* 64 near pointer to 64-bit complex */
#define T_64PCPLX80         0x0652  /* 64 near pointer to 80-bit complex */
#define T_64PCPLX128        0x0653  /* 64 near pointer to 128-bit complex */
#define T_64PRCHAR          0x0670  /* 64 near pointer to a real char */
#define T_64PWCHAR          0x0671  /* 64 near pointer to a wide char */
#define T_64PINT2           0x0672  /* 64 near pointer to 16-bit signed int */
#define T_64PUINT2          0x0673  /* 64 near pointer to 16-bit unsigned int */
#define T_64PINT4           0x0674  /* 64 near pointer to 32-bit signed int */
#define T_64PUINT4          0x0675  /* 64 near pointer to 32-bit unsigned int */
#define T_64PINT8           0x0676  /* 64 near pointer to 64-bit signed int */
#define T_64PUINT8          0x0677  /* 64 near pointer to 64-bit unsigned int */
#define T_64PCHAR16         0x067a  /* 64 near pointer to 16-bit unicode char */
#define T_64PCHAR32         0x067b  /* 64 near pointer to 32-bit unicode char */
#define T_64PCHAR8          0x067c  /* 64 near pointer to 8-bit unicode char */

/* counts, bit masks, and shift values needed to access various parts of the built-in type numbers */
#define T_FIRSTDEFINABLETYPE 0x1000 /* first type index that's not predefined */
#define T_MAXPREDEFINEDTYPE 0x0680  /* maximum type index for all built-in types */
#define T_MAXBASICTYPE      0x0080  /* maximum type index all non-pointer built-in types */
#define T_BASICTYPE_MASK    0x00ff  /* mask of bits that can potentially identify a non-pointer basic type */
#define T_BASICTYPE_SHIFT   8       /* shift count to push out the basic type bits from a type number */
#define T_MODE_MASK         0x0700  /* type mode mask (ptr/non-ptr) */
#define T_SIZE_MASK         0x0007  /* type size mask (depends on 'type' value) */
#define T_TYPE_MASK         0x00f0  /* type type mask (data treatment mode) */

/* bit patterns for the <mode> portion of a built-in type number */
#define T_NEARPTR_BITS      0x0100
#define T_FARPTR_BITS       0x0200
#define T_HUGEPTR_BITS      0x0300
#define T_NEAR32PTR_BITS    0x0400
#define T_FAR32PTR_BITS     0x0500
#define T_NEAR64PTR_BITS    0x0600

#define LF_MODIFIER_V1          0x0001
#define LF_POINTER_V1           0x0002
#define LF_ARRAY_V1             0x0003
#define LF_CLASS_V1             0x0004
#define LF_STRUCTURE_V1         0x0005
#define LF_UNION_V1             0x0006
#define LF_ENUM_V1              0x0007
#define LF_PROCEDURE_V1         0x0008
#define LF_MFUNCTION_V1         0x0009
#define LF_VTSHAPE_V1           0x000a
#define LF_COBOL0_V1            0x000b
#define LF_COBOL1_V1            0x000c
#define LF_BARRAY_V1            0x000d
#define LF_LABEL_V1             0x000e
#define LF_NULL_V1              0x000f
#define LF_NOTTRAN_V1           0x0010
#define LF_DIMARRAY_V1          0x0011
#define LF_VFTPATH_V1           0x0012
#define LF_PRECOMP_V1           0x0013
#define LF_ENDPRECOMP_V1        0x0014
#define LF_OEM_V1               0x0015
#define LF_TYPESERVER_V1        0x0016

#define LF_MODIFIER_V2          0x1001     /* variants with new 32-bit type indices (V2) */
#define LF_POINTER_V2           0x1002
#define LF_ARRAY_V2             0x1003
#define LF_CLASS_V2             0x1004
#define LF_STRUCTURE_V2         0x1005
#define LF_UNION_V2             0x1006
#define LF_ENUM_V2              0x1007
#define LF_PROCEDURE_V2         0x1008
#define LF_MFUNCTION_V2         0x1009
#define LF_COBOL0_V2            0x100a
#define LF_BARRAY_V2            0x100b
#define LF_DIMARRAY_V2          0x100c
#define LF_VFTPATH_V2           0x100d
#define LF_PRECOMP_V2           0x100e
#define LF_OEM_V2               0x100f

#define LF_SKIP_V1              0x0200
#define LF_ARGLIST_V1           0x0201
#define LF_DEFARG_V1            0x0202
#define LF_LIST_V1              0x0203
#define LF_FIELDLIST_V1         0x0204
#define LF_DERIVED_V1           0x0205
#define LF_BITFIELD_V1          0x0206
#define LF_METHODLIST_V1        0x0207
#define LF_DIMCONU_V1           0x0208
#define LF_DIMCONLU_V1          0x0209
#define LF_DIMVARU_V1           0x020a
#define LF_DIMVARLU_V1          0x020b
#define LF_REFSYM_V1            0x020c

#define LF_SKIP_V2              0x1200    /* variants with new 32-bit type indices (V2) */
#define LF_ARGLIST_V2           0x1201
#define LF_DEFARG_V2            0x1202
#define LF_FIELDLIST_V2         0x1203
#define LF_DERIVED_V2           0x1204
#define LF_BITFIELD_V2          0x1205
#define LF_METHODLIST_V2        0x1206
#define LF_DIMCONU_V2           0x1207
#define LF_DIMCONLU_V2          0x1208
#define LF_DIMVARU_V2           0x1209
#define LF_DIMVARLU_V2          0x120a

/* Field lists */
#define LF_BCLASS_V1            0x0400
#define LF_VBCLASS_V1           0x0401
#define LF_IVBCLASS_V1          0x0402
#define LF_ENUMERATE_V1         0x0403
#define LF_FRIENDFCN_V1         0x0404
#define LF_INDEX_V1             0x0405
#define LF_MEMBER_V1            0x0406
#define LF_STMEMBER_V1          0x0407
#define LF_METHOD_V1            0x0408
#define LF_NESTTYPE_V1          0x0409
#define LF_VFUNCTAB_V1          0x040a
#define LF_FRIENDCLS_V1         0x040b
#define LF_ONEMETHOD_V1         0x040c
#define LF_VFUNCOFF_V1          0x040d
#define LF_NESTTYPEEX_V1        0x040e
#define LF_MEMBERMODIFY_V1      0x040f

#define LF_BCLASS_V2            0x1400    /* variants with new 32-bit type indices (V2) */
#define LF_VBCLASS_V2           0x1401
#define LF_IVBCLASS_V2          0x1402
#define LF_FRIENDFCN_V2         0x1403
#define LF_INDEX_V2             0x1404
#define LF_MEMBER_V2            0x1405
#define LF_STMEMBER_V2          0x1406
#define LF_METHOD_V2            0x1407
#define LF_NESTTYPE_V2          0x1408
#define LF_VFUNCTAB_V2          0x1409
#define LF_FRIENDCLS_V2         0x140a
#define LF_ONEMETHOD_V2         0x140b
#define LF_VFUNCOFF_V2          0x140c
#define LF_NESTTYPEEX_V2        0x140d

#define LF_ENUMERATE_V3         0x1502
#define LF_ARRAY_V3             0x1503
#define LF_CLASS_V3             0x1504
#define LF_STRUCTURE_V3         0x1505
#define LF_UNION_V3             0x1506
#define LF_ENUM_V3              0x1507
#define LF_FRIENDFCN_V3         0x150c
#define LF_MEMBER_V3            0x150d
#define LF_STMEMBER_V3          0x150e
#define LF_METHOD_V3            0x150f
#define LF_NESTTYPE_V3          0x1510
#define LF_ONEMETHOD_V3         0x1511
#define LF_VFTABLE_V3           0x151d

/* leaves found in second type type (aka IPI)
 * for simplicity, stored in the same union as other TPI leaves
 */
#define LF_FUNC_ID              0x1601
#define LF_MFUNC_ID             0x1602
#define LF_BUILDINFO            0x1603
#define LF_SUBSTR_LIST          0x1604
#define LF_STRING_ID            0x1605
#define LF_UDT_SRC_LINE         0x1606
#define LF_UDT_MOD_SRC_LINE     0x1607

#define LF_NUMERIC              0x8000    /* numeric leaf types */
#define LF_CHAR                 0x8000
#define LF_SHORT                0x8001
#define LF_USHORT               0x8002
#define LF_LONG                 0x8003
#define LF_ULONG                0x8004
#define LF_REAL32               0x8005
#define LF_REAL64               0x8006
#define LF_REAL80               0x8007
#define LF_REAL128              0x8008
#define LF_QUADWORD             0x8009
#define LF_UQUADWORD            0x800a
#define LF_REAL48               0x800b
#define LF_COMPLEX32            0x800c
#define LF_COMPLEX64            0x800d
#define LF_COMPLEX80            0x800e
#define LF_COMPLEX128           0x800f
#define LF_VARSTRING            0x8010
#define LF_OCTWORD              0x8017
#define LF_UOCTWORD             0x8018
#define LF_DECIMAL              0x8019
#define LF_DATE                 0x801a
#define LF_UTF8STRING           0x801b
#define LF_REAL16               0x801c

/* symtype e.g. for public_vx.symtype */
#define SYMTYPE_NONE            0x0000
#define SYMTYPE_CODE            0x0001
#define SYMTYPE_FUNCTION        0x0002
#define SYMTYPE_MANAGED         0x0004
#define SYMTYPE_MSIL            0x0008

/* ======================================== *
 *            Symbol information
 * ======================================== */

struct cv_addr_range
{
    unsigned int                offStart;
    unsigned short              isectStart;
    unsigned short              cbRange;
};

struct cv_addr_gap
{
    unsigned short              gapStartOffset;
    unsigned short              cbRange;
};

struct cv_local_varflag
{
    unsigned short is_param          : 1;
    unsigned short address_taken     : 1;
    unsigned short from_compiler     : 1; /* generated by compiler */
    unsigned short is_aggregate      : 1; /* split in several variables by compiler */
    unsigned short from_aggregate    : 1; /* marks a temporary from an aggregate */
    unsigned short is_aliased        : 1;
    unsigned short from_alias        : 1;
    unsigned short is_return_value   : 1;
    unsigned short optimized_out     : 1;
    unsigned short enreg_global      : 1; /* global variable accessed from register */
    unsigned short enreg_static      : 1;

    unsigned short unused            : 5;

};

union codeview_symbol
{
    struct
    {
        unsigned short int      len;
        unsigned short int      id;
    } generic;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;
	unsigned int	        offset;
	unsigned short	        segment;
	cv_typ16_t	        symtype;
        struct p_string         p_name;
    } data_v1;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;
	cv_typ_t	        symtype;
	unsigned int	        offset;
	unsigned short	        segment;
        struct p_string         p_name;
    } data_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[];
    } data_v3;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        thunk_len;
	unsigned char	        thtype;
        struct p_string         p_name;
    } thunk_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pparent;
        unsigned int            pend;
        unsigned int            next;
        unsigned int            offset;
        unsigned short          segment;
        unsigned short          thunk_len;
        unsigned char           thtype;
        char                    name[];
    } thunk_v3;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        proc_len;
	unsigned int	        debug_start;
	unsigned int	        debug_end;
	unsigned int	        offset;
	unsigned short	        segment;
	cv_typ16_t	        proctype;
	unsigned char	        flags;
        struct p_string         p_name;
    } proc_v1;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        proc_len;
	unsigned int	        debug_start;
	unsigned int	        debug_end;
	cv_typ_t	        proctype;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned char	        flags;
        struct p_string         p_name;
    } proc_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pparent;
        unsigned int            pend;
        unsigned int            next;
        unsigned int            proc_len;
        unsigned int            debug_start;
        unsigned int            debug_end;
        cv_typ_t                proctype;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        char                    name[];
    } proc_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned short          pubsymflags;
        struct p_string         p_name;
    } public_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pubsymflags;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } public_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pubsymflags;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[];
    } public_v3;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;		/* Always S_BPREL32_16t */
	unsigned int	        offset;	        /* Stack offset relative to BP */
	cv_typ16_t	        symtype;
        struct p_string         p_name;
    } stack_v1;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;		/* Always S_BPREL32_ST */
	unsigned int	        offset;	        /* Stack offset relative to EBP */
	cv_typ_t	        symtype;
        struct p_string         p_name;
    } stack_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;             /* Always S_BPREL32 */
        int                     offset;         /* Stack offset relative to BP */
        cv_typ_t                symtype;
        char                    name[];
    } stack_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;             /* Always S_BPREL32 */
        int                     offset;         /* Stack offset relative to BP */
        cv_typ_t                symtype;
        unsigned short          reg;
        char                    name[];
    } regrel_v3;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;		/* Always S_REGISTER */
        cv_typ16_t              type;
        unsigned short          reg;
        struct p_string         p_name;
        /* don't handle register tracking */
    } register_v1;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;		/* Always S_REGISTER_ST */
        cv_typ_t                type;           /* check whether type & reg are correct */
        unsigned short          reg;
        struct p_string         p_name;
        /* don't handle register tracking */
    } register_v2;

    struct
    {
	unsigned short int      len;
	unsigned short int      id;		/* Always S_REGISTER */
        cv_typ_t                type;           /* check whether type & reg are correct */
        unsigned short          reg;
        char                    name[];
        /* don't handle register tracking */
    } register_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            parent;
        unsigned int            end;
        unsigned int            length;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } block_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            parent;
        unsigned int            end;
        unsigned int            length;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[];
    } block_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned short          trampType; /* 0: incremental, 1: branchisland */
        unsigned short          cbThunk;
        unsigned int            offThunk;
        unsigned int            offTarget;
        unsigned short          sectThunk;
        unsigned short          sectTarget;
    } trampoline_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        struct p_string         p_name;
    } label_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        char                    name[];
    } label_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ16_t              type;
        unsigned char           data[];
        /* <numeric leaf>       cvalue; */
        /* struct p_string      p_name; */
    } constant_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        unsigned char           data[];
        /* <numeric leaf>       cvalue; */
        /* struct p_string      p_name; */
    } constant_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        unsigned char           data[];
        /* <numeric leaf>       cvalue; */
        /* char                 name; */
    } constant_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ16_t              type;
        struct p_string         p_name;
    } udt_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        struct p_string         p_name;
    } udt_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                type;
        char                    name[];
    } udt_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned                signature;
        struct p_string         p_name;
    } objname_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned                signature;
        char                    name[];
    } objname_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned char           machine;
        struct
        {
        unsigned char           language : 8;
        unsigned char           _dome : 8; /* other missing fields */
        unsigned char           pad : 8;
        } flags;
        struct p_string         p_name;
    } compile_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        struct {
        unsigned int            iLanguage :  8;
        unsigned int            _dome     :  9; /* other missing fields */
        unsigned int            pad       : 15;
        } flags;
        unsigned short          machine;
        unsigned short          fe_major;
        unsigned short          fe_minor;
        unsigned short          fe_build;
        unsigned short          be_major;
        unsigned short          be_minor;
        unsigned short          be_build;
        struct p_string         p_name;
    } compile2_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        struct {
        unsigned int            iLanguage :  8;
        unsigned int            _dome     :  9; /* other missing fields */
        unsigned int            pad       : 15;
        } flags;
        unsigned short          machine;
        unsigned short          fe_major;
        unsigned short          fe_minor;
        unsigned short          fe_build;
        unsigned short          be_major;
        unsigned short          be_minor;
        unsigned short          be_build;
        char                    name[];
    } compile2_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        struct {
        unsigned int            iLanguage :  8;
        unsigned int            _dome     : 12; /* other missing fields */
        unsigned int            pad       : 12;
        } flags;
        unsigned short          machine;
        unsigned short          fe_major;
        unsigned short          fe_minor;
        unsigned short          fe_build;
        unsigned short          fe_qfe;
        unsigned short          be_major;
        unsigned short          be_minor;
        unsigned short          be_build;
        unsigned short          be_qfe;
        char                    name[];
    } compile3_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned short          segment;
        cv_typ16_t              symtype;
        struct p_string         p_name;
    } thread_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                symtype;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } thread_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[];
    } thread_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            sumName;
        unsigned int            ibSym;
        unsigned short          imod;
        char                    name[];
    } refsym2_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned short          segment;
    } ssearch_v1;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned int            unknown;
    } security_cookie_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            sz_frame;       /* size of frame */
        unsigned int            unknown2;
        unsigned int            unknown3;
        unsigned int            sz_saved_regs;  /* size of saved registers from callee */
        unsigned int            eh_offset;      /* offset for exception handler */
        unsigned short          eh_sect;        /* section for exception handler */
        unsigned int            flags;
    } frame_info_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            offset;
        unsigned short          sect_idx;
        unsigned short          inst_len;
        cv_typ_t                index;
    } heap_alloc_site_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                symtype;
        struct cv_local_varflag varflags;
        char                    name[];
    } local_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            program;
        struct cv_addr_range    range;
        struct cv_addr_gap      gaps[];
    } defrange_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            program;
        unsigned int            offParent;
        struct cv_addr_range    range;
        struct cv_addr_gap      gaps[];
    } defrange_subfield_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned short          reg;
        unsigned short          attr;
        struct cv_addr_range    range;
        struct cv_addr_gap      gaps[];
    } defrange_register_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        int                     offFramePointer;
        struct cv_addr_range    range;
        struct cv_addr_gap      gaps[];
    } defrange_frameptrrel_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        int                     offFramePointer;
    } defrange_frameptr_relfullscope_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned short          reg;
        unsigned short          attr;
        unsigned int            offParent : 12;
        unsigned int            padding   : 20;
        struct cv_addr_range    range;
        struct cv_addr_gap      gaps[];
    } defrange_subfield_register_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned short          baseReg;
        unsigned short          spilledUdtMember : 1;
        unsigned short          padding          : 3;
        unsigned short          offsetParent     : 12;
        int                     offBasePointer;
        struct cv_addr_range    range;
        struct cv_addr_gap      gaps[];
    } defrange_registerrel_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_itemid_t             itemid;
    } build_info_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pParent;
        unsigned int            pEnd;
        cv_itemid_t             inlinee;
        unsigned char           binaryAnnotations[];
    } inline_site_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      typ;
        unsigned int            off;
        unsigned short          sect;
        unsigned short          _pad0;
        cv_typ_t                typind;
    } callsiteinfo_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pParent;
        unsigned int            pEnd;
        cv_itemid_t             inlinee;
        unsigned int            invocations;
        unsigned char           binaryAnnotations[];
    } inline_site2_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            count;
        unsigned char           data[];
        /* cv_typ_t             functions[count]; */
        /* unsigned int         invocations[count]; */
    } function_list_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        cv_typ_t                typind;
        unsigned int            modOffset;
        struct cv_local_varflag varflags;
        char                    name[];
    } file_static_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        struct p_string         pname;
    } unamespace_v2;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        char                    name[];
    } unamespace_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            pParent;
        unsigned int            pEnd;
        unsigned int            length;
        unsigned int            scf; /* CV_SEPCODEFLAGS */
        unsigned int            off;
        unsigned int            offParent;
        unsigned short int      sect;
        unsigned short int      sectParent;
    } sepcode_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            off;
        unsigned short int      seg;
        unsigned short int      csz; /* number of bytes in following array */
        char                    rgsz[]; /* array of null terminated strings (bounded by csz) */
    } annotation_v3;

    struct
    {
        unsigned short int      len;
        unsigned short int      id;
        unsigned int            invocations;
        __int64                 dynCount;
        unsigned                numInstrs;
        unsigned                staInstLive;
    } pogoinfo_v3;
};

enum BinaryAnnotationOpcode
{
    BA_OP_Invalid,
    BA_OP_CodeOffset,
    BA_OP_ChangeCodeOffsetBase,
    BA_OP_ChangeCodeOffset,
    BA_OP_ChangeCodeLength,
    BA_OP_ChangeFile,
    BA_OP_ChangeLineOffset,
    BA_OP_ChangeLineEndDelta,
    BA_OP_ChangeRangeKind,
    BA_OP_ChangeColumnStart,
    BA_OP_ChangeColumnEndDelta,
    BA_OP_ChangeCodeOffsetAndLineOffset,
    BA_OP_ChangeCodeLengthAndCodeOffset,
    BA_OP_ChangeColumnEnd,
};

#define S_COMPILE       0x0001
#define S_REGISTER_16t  0x0002
#define S_CONSTANT_16t  0x0003
#define S_UDT_16t       0x0004
#define S_SSEARCH       0x0005
#define S_END           0x0006
#define S_SKIP          0x0007
#define S_CVRESERVE     0x0008
#define S_OBJNAME_ST    0x0009
#define S_ENDARG        0x000a
#define S_COBOLUDT_16t  0x000b
#define S_MANYREG_16t   0x000c
#define S_RETURN        0x000d
#define S_ENTRYTHIS     0x000e

#define S_BPREL32_16t   0x0200
#define S_LDATA32_16t   0x0201
#define S_GDATA32_16t   0x0202
#define S_PUB32_16t     0x0203
#define S_LPROC32_16t   0x0204
#define S_GPROC32_16t   0x0205
#define S_THUNK32_ST    0x0206
#define S_BLOCK32_ST    0x0207
#define S_WITH32_ST     0x0208
#define S_LABEL32_ST    0x0209
#define S_CEXMODEL32    0x020a
#define S_VFTABLE32_16t 0x020b
#define S_REGREL32_16t  0x020c
#define S_LTHREAD32_16t 0x020d
#define S_GTHREAD32_16t 0x020e

#define S_PROCREF_ST    0x0400
#define S_DATAREF_ST    0x0401
#define S_ALIGN         0x0402
#define S_LPROCREF_ST   0x0403

#define S_REGISTER_ST   0x1001 /* Variants with new 32-bit type indices */
#define S_CONSTANT_ST   0x1002
#define S_UDT_ST        0x1003
#define S_COBOLUDT_ST   0x1004
#define S_MANYREG_ST    0x1005
#define S_BPREL32_ST    0x1006
#define S_LDATA32_ST    0x1007
#define S_GDATA32_ST    0x1008
#define S_PUB32_ST      0x1009
#define S_LPROC32_ST    0x100a
#define S_GPROC32_ST    0x100b
#define S_VFTABLE32     0x100c
#define S_REGREL32_ST   0x100d
#define S_LTHREAD32_ST  0x100e
#define S_GTHREAD32_ST  0x100f
#define S_FRAMEPROC     0x1012
#define S_COMPILE2_ST   0x1013
#define S_ANNOTATION    0x1019
#define S_UNAMESPACE_ST 0x1029

#define S_OBJNAME       0x1101
#define S_THUNK32       0x1102
#define S_BLOCK32       0x1103
#define S_WITH32        0x1104
#define S_LABEL32       0x1105
#define S_REGISTER      0x1106
#define S_CONSTANT      0x1107
#define S_UDT           0x1108
#define S_COBOLUDT      0x1109
#define S_MANYREG       0x110A
#define S_BPREL32       0x110B
#define S_LDATA32       0x110C
#define S_GDATA32       0x110D
#define S_PUB32         0x110E
#define S_LPROC32       0x110F
#define S_GPROC32       0x1110
#define S_REGREL32      0x1111
#define S_LTHREAD32     0x1112
#define S_GTHREAD32     0x1113
#define S_LPROCMIPS     0x1114
#define S_GPROCMIPS     0x1115
#define S_COMPILE2      0x1116  /* compiler command line options and build information */
#define S_MANYREG2      0x1117
#define S_LPROCIA64     0x1118
#define S_GPROCIA64     0x1119
#define S_LOCALSLOT     0x111A
#define S_PARAMSLOT     0x111B
#define S_LMANDATA      0x111C
#define S_GMANDATA      0x111D
#define S_MANFRAMEREL   0x111E
#define S_MANREGISTER   0x111F
#define S_MANSLOT       0x1120
#define S_MANMANYREG    0x1121
#define S_MANREGREL     0x1122
#define S_MANMANYREG2   0x1123
#define S_UNAMESPACE    0x1124
#define S_PROCREF       0x1125  /* didn't get the difference between the two */
#define S_DATAREF       0x1126
#define S_LPROCREF      0x1127
#define S_ANNOTATIONREF 0x1128
#define S_TOKENREF      0x1129
#define S_GMANPROC      0x112A
#define S_LMANPROC      0x112B
#define S_TRAMPOLINE    0x112C
#define S_MANCONSTANT   0x112D
#define S_ATTR_FRAMEREL 0x112E
#define S_ATTR_REGISTER 0x112F
#define S_ATTR_REGREL   0x1130
#define S_ATTR_MANYREG  0x1131
#define S_SEPCODE       0x1132
#define S_LOCAL_2005    0x1133
#define S_DEFRANGE_2005 0x1134
#define S_DEFRANGE2_2005 0x1135
#define S_SECTION       0x1136
#define S_COFFGROUP     0x1137
#define S_EXPORT        0x1138
#define S_CALLSITEINFO  0x1139
#define S_FRAMECOOKIE   0x113A
#define S_DISCARDED     0x113B
#define S_COMPILE3      0x113C
#define S_ENVBLOCK      0x113D

#define S_LOCAL             0x113E
#define S_DEFRANGE          0x113F
#define S_DEFRANGE_SUBFIELD 0x1140
#define S_DEFRANGE_REGISTER 0x1141
#define S_DEFRANGE_FRAMEPOINTER_REL     0x1142
#define S_DEFRANGE_SUBFIELD_REGISTER    0x1143
#define S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE      0x1144
#define S_DEFRANGE_REGISTER_REL         0x1145
#define S_LPROC32_ID        0x1146
#define S_GPROC32_ID        0x1147
#define S_LPROCMIPS_ID      0x1148
#define S_GPROCMIPS_ID      0x1149
#define S_LPROCIA64_ID      0x114A
#define S_GPROCIA64_ID      0x114B
#define S_BUILDINFO         0x114C
#define S_INLINESITE        0x114D
#define S_INLINESITE_END    0x114E
#define S_PROC_ID_END       0x114F
#define S_DEFRANGE_HLSL     0x1150
#define S_GDATA_HLSL        0x1151
#define S_LDATA_HLSL        0x1152

#define S_FILESTATIC        0x1153
#define S_ARMSWITCHTABLE    0x1159
#define S_CALLEES           0x115A
#define S_CALLERS           0x115B
#define S_POGODATA          0x115C
#define S_INLINESITE2       0x115D
#define S_HEAPALLOCSITE     0x115E
#define S_MOD_TYPEREF       0x115F
#define S_REF_MINIPDB       0x1160
#define S_PDBMAP            0x1161
#define S_GDATA_HLSL32      0x1162
#define S_LDATA_HLSL32      0x1163
#define S_GDATA_HLSL32_EX   0x1164
#define S_LDATA_HLSL32_EX   0x1165

/* not documented yet on MS CV github repo, but that's how LLVM calls it */
#define S_INLINEES          0x1168

/* ======================================== *
 *          Line number information
 * ======================================== */

enum DEBUG_S_SUBSECTION_TYPE
{
    DEBUG_S_IGNORE = 0x80000000,    /* bit flag: when set, ignore whole subsection content */

    DEBUG_S_SYMBOLS = 0xf1,
    DEBUG_S_LINES,
    DEBUG_S_STRINGTABLE,
    DEBUG_S_FILECHKSMS,
    DEBUG_S_FRAMEDATA,
    DEBUG_S_INLINEELINES,
    DEBUG_S_CROSSSCOPEIMPORTS,
    DEBUG_S_CROSSSCOPEEXPORTS,

    DEBUG_S_IL_LINES,
    DEBUG_S_FUNC_MDTOKEN_MAP,
    DEBUG_S_TYPE_MDTOKEN_MAP,
    DEBUG_S_MERGED_ASSEMBLYINPUT,

    DEBUG_S_COFF_SYMBOL_RVA,
};

struct CV_DebugSSubsectionHeader_t
{
    enum DEBUG_S_SUBSECTION_TYPE type;
    unsigned                     cbLen;
};

struct CV_DebugSLinesHeader_t
{
    unsigned       offCon;
    unsigned short segCon;
    unsigned short flags;
    unsigned       cbCon;
};

struct CV_DebugSLinesFileBlockHeader_t
{
    unsigned       offFile;
    unsigned       nLines;
    unsigned       cbBlock;
    /* followed by two variable length arrays
     * CV_Line_t      lines[nLines];
     * ^ columns present when CV_DebugSLinesHeader_t.flags has CV_LINES_HAVE_COLUMNS set
     * CV_Column_t    columns[nLines];
     */
};

#define CV_LINES_HAVE_COLUMNS 0x0001

struct CV_Line_t
{
    unsigned   offset;
    unsigned   linenumStart:24;
    unsigned   deltaLineEnd:7;
    unsigned   fStatement:1;
};

struct CV_Column_t
{
    unsigned short offColumnStart;
    unsigned short offColumnEnd;
};

struct CV_Checksum_t /* this one is not defined in microsoft pdb information */
{
    unsigned            strOffset;      /* offset in string table for filename */
    unsigned char       size;           /* size of checksum */
    unsigned char       method;         /* method used to compute check sum */
    unsigned char       checksum[];     /* (size) bytes */
    /* result is padded on 4-byte boundary */
};

#define CV_INLINEE_SOURCE_LINE_SIGNATURE     0x0
#define CV_INLINEE_SOURCE_LINE_SIGNATURE_EX  0x1

typedef struct CV_InlineeSourceLine_t
{
    cv_itemid_t    inlinee;       /* function id */
    unsigned       fileId;        /* offset in DEBUG_S_FILECHKSMS */
    unsigned       sourceLineNum; /* first line number */
} InlineeSourceLine;

typedef struct CV_InlineeSourceLineEx_t
{
    cv_itemid_t    inlinee;       /* function id */
    unsigned       fileId;        /* offset in DEBUG_S_FILECHKSMS */
    unsigned       sourceLineNum; /* first line number */
    unsigned int   countOfExtraFiles;
    unsigned       extraFileId[];
} InlineeSourceLineEx;

#ifdef __WINESRC__
/* those are Wine only helpers */
/* align ptr on sz boundary; sz must be a power of 2 */
#define CV_ALIGN(ptr, sz)            ((const void*)(((DWORD_PTR)(ptr) + ((sz) - 1)) & ~((sz) - 1)))
/* move after (ptr) record */
#define CV_RECORD_AFTER(ptr)         ((const void*)((ptr) + 1))
/* move after (ptr) record and a gap of sz bytes */
#define CV_RECORD_GAP(ptr, sz)       ((const void*)((const char*)((ptr) + 1) + (sz)))
/* test whether ptr record is within limit boundary */
#define CV_IS_INSIDE(ptr, limit)     (CV_RECORD_AFTER(ptr) <= (const void*)(limit))
#endif /* __WINESRC__ */

struct codeview_linetab_block
{
    unsigned short              seg;
    unsigned short              num_lines;
    unsigned char               data[];
    /* unsigned int             offsets[num_lines]; */
    /* unsigned short           linenos[]; */
};

struct startend
{
    unsigned int	        start;
    unsigned int	        end;
};

/* ======================================== *
 *            PDB file information
 * ======================================== */


struct PDB_JG_STREAM
{
    unsigned int        size;
    unsigned int        unknown;
};

struct PDB_JG_HEADER
{
    char                ident[40];
    unsigned int        signature;
    unsigned int        block_size;
    unsigned short      free_list_block;
    unsigned short      total_alloc;
    struct PDB_JG_STREAM toc;
    /* unsigned short      toc_block[]; */
};

struct PDB_DS_HEADER
{
    char                signature[32];
    unsigned int        block_size;
    unsigned int        free_list_block;
    unsigned int        num_blocks;
    unsigned int        toc_size;
    unsigned int        unknown2;
    unsigned int        toc_block;
};

struct PDB_JG_TOC
{
    unsigned int        num_streams;
    struct PDB_JG_STREAM streams[];
};

struct PDB_DS_TOC
{
    unsigned int        num_streams;
    unsigned int        stream_size[];
};

struct PDB_JG_ROOT
{
    unsigned int        Version;
    unsigned int        TimeDateStamp;
    unsigned int        Age;
    unsigned int        cbNames;
    char                names[];
};

struct PDB_DS_ROOT
{
    unsigned int        Version;
    unsigned int        TimeDateStamp;
    unsigned int        Age;
    GUID                guid;
    unsigned int        cbNames;
    char                names[];
};

typedef struct _PDB_TYPES_OLD
{
    unsigned int   version;
    unsigned short first_index;
    unsigned short last_index;
    unsigned int   type_size;
    unsigned short hash_stream;
    unsigned short pad;
} PDB_TYPES_OLD, *PPDB_TYPES_OLD;

typedef struct _PDB_TYPES
{
    unsigned int   version;
    unsigned int   type_offset;
    unsigned int   first_index;
    unsigned int   last_index;
    unsigned int   type_size;
    unsigned short hash_stream;
    unsigned short pad;
    unsigned int   hash_value_size;
    unsigned int   hash_num_buckets;
    unsigned int   hash_offset;
    unsigned int   hash_size;
    unsigned int   search_offset;
    unsigned int   search_size;
    unsigned int   type_remap_offset;
    unsigned int   type_remap_size;
} PDB_TYPES, *PPDB_TYPES;

typedef struct _PDB_SYMBOL_RANGE
{
    unsigned short segment;
    unsigned short pad1;
    unsigned int   offset;
    unsigned int   size;
    unsigned int   characteristics;
    unsigned short index;
    unsigned short pad2;
} PDB_SYMBOL_RANGE, *PPDB_SYMBOL_RANGE;

typedef struct _PDB_SYMBOL_RANGE_EX
{
    unsigned short segment;
    unsigned short pad1;
    unsigned int   offset;
    unsigned int   size;
    unsigned int   characteristics;
    unsigned short index;
    unsigned short pad2;
    unsigned int   timestamp;
    unsigned int   unknown;
} PDB_SYMBOL_RANGE_EX, *PPDB_SYMBOL_RANGE_EX;

typedef struct _PDB_SYMBOL_FILE
{
    unsigned int     unknown1;
    PDB_SYMBOL_RANGE range;
    unsigned short   flag;
    unsigned short   stream;
    unsigned int     symbol_size;
    unsigned int     lineno_size;
    unsigned int     lineno2_size;
    unsigned int     nSrcFiles;
    unsigned int     attribute;
    char             filename[];
} PDB_SYMBOL_FILE, *PPDB_SYMBOL_FILE;

typedef struct _PDB_SYMBOL_FILE_EX
{
    unsigned int        unknown1;
    PDB_SYMBOL_RANGE_EX range;
    unsigned short      flag;
    unsigned short      stream;
    unsigned int        symbol_size;
    unsigned int        lineno_size;
    unsigned int        lineno2_size;
    unsigned int        nSrcFiles;
    unsigned int        attribute;
    unsigned int        reserved[2];
    char                filename[];
} PDB_SYMBOL_FILE_EX, *PPDB_SYMBOL_FILE_EX;

typedef struct _PDB_SYMBOL_SOURCE
{
    unsigned short        nModules;
    unsigned short        nSrcFiles;
    unsigned short        table[];
} PDB_SYMBOL_SOURCE, *PPDB_SYMBOL_SOURCE;

typedef struct _PDB_SYMBOL_IMPORT
{
    unsigned int unknown1;
    unsigned int unknown2;
    unsigned int TimeDateStamp;
    unsigned int Age;
    char         filename[];
} PDB_SYMBOL_IMPORT, *PPDB_SYMBOL_IMPORT;

typedef struct _PDB_SYMBOLS_OLD
{
    unsigned short global_hash_stream;
    unsigned short public_stream;
    unsigned short gsym_stream;
    unsigned short pad;
    unsigned int   module_size;
    unsigned int   sectcontrib_size;
    unsigned int   segmap_size;
    unsigned int   srcmodule_size;
} PDB_SYMBOLS_OLD, *PPDB_SYMBOLS_OLD;

typedef struct _PDB_SYMBOLS
{
    unsigned int   signature;
    unsigned int   version;
    unsigned int   age;
    unsigned short global_hash_stream;
    unsigned short flags;
    unsigned short public_stream;
    unsigned short bldVer;
    unsigned short gsym_stream;
    unsigned short rbldVer;
    unsigned int   module_size;
    unsigned int   sectcontrib_size;
    unsigned int   segmap_size;
    unsigned int   srcmodule_size;
    unsigned int   pdbimport_size;
    unsigned int   resvd0;
    unsigned int   stream_index_size;
    unsigned int   unknown2_size;
    unsigned short resvd3;
    unsigned short machine;
    unsigned int   resvd4;
} PDB_SYMBOLS, *PPDB_SYMBOLS;

/* FIXME other entries are unknown */
enum PDB_STREAM_INDEX
{
    PDB_SIDX_FPO,
    PDB_SIDX_SECTIONS = 5,
    PDB_SIDX_FPOEXT = 9
};

typedef struct _PDB_FPO_DATA
{
    unsigned int   start;
    unsigned int   func_size;
    unsigned int   locals_size;
    unsigned int   params_size;
    unsigned int   maxstack_size;
    unsigned int   str_offset;
    unsigned short prolog_size;
    unsigned short savedregs_size;
#define PDB_FPO_DFL_SEH         0x00000001
#define PDB_FPO_DFL_EH          0x00000002
#define PDB_FPO_DFL_IN_BLOCK    0x00000004
    unsigned int   flags;
} PDB_FPO_DATA;

typedef struct _PDB_STRING_TABLE
{
    unsigned int   magic;
    unsigned int   hash_version;
    unsigned int   length;
}
PDB_STRING_TABLE;
/* This header is followed by:
 * - a series (of bytes hdr.length) of 0-terminated strings
 * - a serialized hash table
 */

/* Header for hash tables inside DBI (aka symbols) stream.
 * - The global hash stream contains only the hash table.
 * - The public stream contains the same layout for its hash table
 *   (but other information as well).
 */
typedef struct
{
    unsigned signature;
    unsigned version;
    unsigned hash_records_size;
    unsigned unknown;
} DBI_HASH_HEADER;
/* This header is followed by:
 * - DBI_HASH_RECORDS (on hdr:hash_records_size bytes)
 * - a bitmap of DBI_MAX_HASH + 1 entries (on DBI_BITMAP_HASH_SIZE bytes)
 * - a table (one entry per present bit in bitmap) as index into hdr:num_records
 */

typedef struct
{
    unsigned offset;
    unsigned unknown;
} DBI_HASH_RECORD;

#define DBI_MAX_HASH 4096
#define DBI_BITMAP_HASH_SIZE ((DBI_MAX_HASH / (8 * sizeof(unsigned)) + 1) * sizeof(unsigned))

/* Header for public stream (from DBI / SYMBOLS stream)
 * Followed by a hash table (cf DBI_HASH_HEADER and the following bits)
 */
typedef struct
{
    unsigned hash_size;
    unsigned address_map_size;
    unsigned num_thunks;
    unsigned thunk_size;
    unsigned short section_thunk_table;
    unsigned short _pad0;
    unsigned offset_thunk_table;
    unsigned num_sections;
} DBI_PUBLIC_HEADER;

#pragma pack(pop)

/* ===================================================
 * The old CodeView stuff (for NB09 and NB11)
 * =================================================== */

#define sstModule      0x120
#define sstTypes       0x121
#define sstPublic      0x122
#define sstPublicSym   0x123
#define sstSymbols     0x124
#define sstAlignSym    0x125
#define sstSrcLnSeg    0x126
#define sstSrcModule   0x127
#define sstLibraries   0x128
#define sstGlobalSym   0x129
#define sstGlobalPub   0x12a
#define sstGlobalTypes 0x12b
#define sstMPC         0x12c
#define sstSegMap      0x12d
#define sstSegName     0x12e
#define sstPreComp     0x12f
#define sstFileIndex   0x133
#define sstStaticSym   0x134

/* overall structure information */
typedef struct OMFSignature
{
    char        Signature[4];
    int         filepos;
} OMFSignature;

typedef struct OMFSignatureRSDS
{
    char         Signature[4];
    GUID         guid;
    unsigned int age;
    char         name[];
} OMFSignatureRSDS;

typedef struct _CODEVIEW_PDB_DATA
{
    char        Signature[4];
    int         filepos;
    unsigned int timestamp;
    unsigned int age;
    char         name[];
} CODEVIEW_PDB_DATA, *PCODEVIEW_PDB_DATA;

typedef struct OMFDirHeader
{
    unsigned short cbDirHeader;
    unsigned short cbDirEntry;
    unsigned int   cDir;
    unsigned int   lfoNextDir;
    unsigned int   flags;
} OMFDirHeader;

typedef struct OMFDirEntry
{
    unsigned short SubSection;
    unsigned short iMod;
    unsigned int   lfo;
    unsigned int   cb;
} OMFDirEntry;

/* sstModule subsection */

typedef struct OMFSegDesc
{
    unsigned short Seg;
    unsigned short pad;
    unsigned int   Off;
    unsigned int   cbSeg;
} OMFSegDesc;

typedef struct OMFModule
{
    unsigned short ovlNumber;
    unsigned short iLib;
    unsigned short cSeg;
    char           Style[2];
/*
    OMFSegDesc  SegInfo[cSeg];
    p_string    Name;
*/
} OMFModule;

typedef struct OMFGlobalTypes
{
    unsigned int flags;
    unsigned int cTypes;
/*
    unsigned int offset[cTypes];
                types_record[];
*/
} OMFGlobalTypes;

/* sstGlobalPub section */

/* Header for symbol table */
typedef struct OMFSymHash
{
    unsigned short  symhash;
    unsigned short  addrhash;
    unsigned int    cbSymbol;
    unsigned int    cbHSym;
    unsigned int    cbHAddr;
} OMFSymHash;

/* sstSegMap section */

typedef struct OMFSegMapDesc
{
    unsigned short  flags;
    unsigned short  ovl;
    unsigned short  group;
    unsigned short  frame;
    unsigned short  iSegName;
    unsigned short  iClassName;
    unsigned int    offset;
    unsigned int    cbSeg;
} OMFSegMapDesc;

typedef struct OMFSegMap
{
    unsigned short  cSeg;
    unsigned short  cSegLog;
/*    OMFSegMapDesc   rgDesc[0];*/
} OMFSegMap;


/* sstSrcModule section */

typedef struct OMFSourceLine
{
    unsigned short  Seg;
    unsigned short  cLnOff;
    unsigned int    offset[];
/*    unsigned short  lineNbr[]; */
} OMFSourceLine;

typedef struct OMFSourceFile
{
    unsigned short  cSeg;
    unsigned short  reserved;
    unsigned int    baseSrcLn[];
/*    unsigned short  cFName; */
/*    char            Name; */
} OMFSourceFile;

typedef struct OMFSourceModule
{
    unsigned short  cFile;
    unsigned short  cSeg;
    unsigned int    baseSrcFile[];
} OMFSourceModule;


/* undocumented. IMAGE_DEBUG_TYPE_REPRO directory entry */
typedef struct
{
    unsigned        flags;           /* only seen 0x20 */
    GUID            guid;            /* guid used in CODEVIEW debug entry */
    unsigned        unk[3];          /* unknown, potentially hash of some internal parts of image */
    unsigned        debug_timestamp; /* used in all DEBUG entries as timestamp (including this one) */
} IMAGE_DEBUG_REPRO;
