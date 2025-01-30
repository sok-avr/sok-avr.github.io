---
layout: default
title: Cases
permalink: /cases/
---


<!-- ### <font color="red">ToDO</font>: Add Cases that the current methods can/can't repair, for future directions, also demonstrate cases -->

> In addition to the cases we listed in the paper, we also analyzed some cases here to show current prevalent LLMs good at what kinds of vulnerabilities and how could we enhance its effectiveness. This not only include the data in our benchmark but also some failure cases in others' AVR work.

- [Summarized cases that learning-based methods can repair](#summarized-cases-that-learning-based-methods-can-repair)
- [Summarized cases that learning-based methods cannot repair](#summarized-cases-that-learning-based-methods-cannot-repair)
- [Summarized cases that non-learning-based methods can repair](#summarized-cases-that-non-learning-based-methods-can-repair)
- [Summarized cases that non-learning-based methods cannot repair](#summarized-cases-that-non-learning-based-methods-cannot-repair)
- [Summary](#summary)
- [Hybrid approach will enhance AVR](#hybrid-approach-will-enhance-avr)


## Summarized cases that learning-based methods can repair

**1. For vulnerabilities with explicit patterns(e.g., security usage of APIs)**

```diff
//VUL4J-35
@@ -51,7 +52,7 @@ public class TokenHelper {
     */
    public static final String TOKEN_NAME_FIELD = "struts.token.name";
    private static final Logger LOG = LoggerFactory.getLogger(TokenHelper.class);
-    private static final Random RANDOM = new Random();
+    private static final Random RANDOM = new SecureRandom();
```
The LLM generate this fix because such patterns often involve widely recommended best practices, such as replacing `Random` with `SecureRandom` in security-sensitive contexts. Also, such fix don't need to consider too much about the dependencies. VUL4J-71 is also such a repair.

VUL4J-51 is also similar:

```diff
@@ -84,9 +84,7 @@ public Collection<FileAnnotation> parse(InputStream file, String moduleName)
	}

	private Ccm parseCCMXmlFile(InputStream ccmXmlFile) throws IOException, SAXException {
-		Digester digester = new Digester();
-		digester.setValidating(false);
-		digester.setClassLoader(CcmParser.class.getClassLoader());
+		SecureDigester digester = new SecureDigester(CcmParser.class);

		String rootXPath = "ccm";
		digester.addObjectCreate(rootXPath, Ccm.class);
```

**2. Built-in Features**
```diff
@@ -238,7 +238,7 @@ private boolean prefersSeekableByteChannel(String format) {
    //VUL4J-5
    private void expand(ArchiveEntrySupplier supplier, EntryWriter writer, File targetDirectory)
        throws IOException {
-        String targetDirPath = targetDirectory.getCanonicalPath();
+        String targetDirPath = targetDirectory.getCanonicalPath() + File.separatorChar;
        ArchiveEntry nextEntry = supplier.getNextReadableEntry();
        while (nextEntry != null) {
            File f = new File(targetDirectory, nextEntry.getName());

```

Analysis: `targetDirectory.getCanonicalPath()` was used to get the canonical path of the target directory, but the path was directly concatenated with the file name without ensuring there was a proper path separator(`\` or `/`), if the `targetDirectory` path did not end with a separator, this could lead to incorrect file paths, potentially causing exceptions or even security risks such as directory traversal attacks. The fix involved appending `File.separatorChar` to the canonical path of targetDirectory. The fix is related to Java’s built-in features `File.separatorChar`, for LLMs such explicit features that related to built-feature/library sometimes is easy to be fixed. But also due to such explicit pattern, for deep learning or other methods, they are also easy to be fixed.

VUL4J-79(CVE-2018-1002201) is also similar cases:

```diff
@@ -1150,6 +1150,15 @@ public void process(InputStream in, ZipEntry zipEntry) throws IOException {
      String name = mapper.map(zipEntry.getName());
      if (name != null) {
        File file = new File(outputDir, name);

       
+        if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {
+          throw new ZipException("The file "+name+" is trying to leave the target output directory of "+outputDir+". Ignoring this file.");
+        }

        if (zipEntry.isDirectory()) {
          FileUtils.forceMkdir(file);
        }
```

VJBench-Halo1 is also similar, which has been fixed successfully

```DIFF
@@ -296,7 +296,7 @@ public static void checkDirectoryTraversal(@NonNull Path parentPath, @NonNull Pa
        Assert.notNull(parentPath, "Parent path must not be null");
        Assert.notNull(pathToCheck, "Path to check must not be null");

-        if (pathToCheck.startsWith(parentPath.normalize())) {
+        if (pathToCheck.normalize().startsWith(parentPath)) {
            return;
        }
```


**3. Simple changes, short context**

For example, [CVE-2018-17202](https://github.com/apache/commons-imaging/commit/6a79d35d6654d895d0a4b73b3a9282ec9aaeeb06):
```diff
//VUL4J-12
@@ -400,7 +400,7 @@ private static int fastRound(final float x) {
    private int extend(int v, final int t) {

        int vt = (1 << (t - 1));
-        while (v < vt) {
+        if (v < vt) {
            vt = (-1 << t) + 1;
            v += vt;
        }
        return v;
    }
```
Analysis: The change mainly transform the `while` loop to `if` condition, This could be repaired by GPT4, CodeT5, and Fine-tuned Incoder.  In the original code, if the input parameter `v` is very small, then `while (v < vt)` may always be `true`, potentially cause infinit loop. So make this simple change. However, the root cause of this vulnerability is mainly the **misunderstanding of [JEPG Sign Extension Standard Section F2.2.1](https://www.w3.org/Graphics/JPEG/itu-t81.pdf)**, where the specification means *Each decoded value needs to be sign-extended **at most once***. Whereas this constraint should be get from *Figure F.12* in the specification. However, even though the models describe above have fixed this, this may because the fix is not complex, and when given the CWE type in the prompt, such fix could be guessed successfully. If there are very long context, the models may not take effective. In this case, we advocate **Better specification Genration**, from the document, the expression are diverse, figures, text, etc. Better specification with the vulnerable code will be better for LLM driven AVR.

[Vul4J-20](https://github.com/apache/commons-imaging/commit/6a79d35d6654d895d0a4b73b3a9282ec9aaeeb06)(CVE-2018-11797) also belongs to this type **Simple changes, short context**, which can be repaired by GPT-4 in our experiment
```diff
@@ -534,9 +534,11 @@ public void setNeedToBeUpdated(boolean flag)
    public float[] toFloatArray()
    {
        float[] retval = new float[size()];
        for (int i = 0; i < size(); i++)
        {
-            retval[i] = ((COSNumber)getObject( i )).floatValue();
+            COSBase base = getObject(i);
+            retval[i] =
+                base instanceof COSNumber ? ((COSNumber) base).floatValue() : 0;
        }
        return retval;
    }
```


## Summarized cases that learning-based methods cannot repair

**1. The vulerability fix should take logic into consideration, however, learning based methods know nothing about with the specification of the vul**

```diff
//CVE-2019-3775
@@ -38,6 +38,10 @@ public boolean isAllowed(HttpServletRequest request) throws IOException {
            return false;
        }

+        if (!scimUserFromDb.getEmails().containsAll(scimUserFromRequest.getEmails())) {
+            return false;
+        }

        if (!scimUserFromDb.getUserName().equals(scimUserFromRequest.getUserName())) {
            return false;
        }
```

Analysis: This vulnerability is due to improper authentication. This patch adds email validation logic to prevent users from updating their email addresses themselves, thereby increasing the security of the system and ensuring that email changes must be performed by authorized entities. However, for learning-based methods, they lack the understanding of the whole code intention, and specifications for this logic. So it is almost impossible for it to implement such fix.

**2. The fix need to consider about inter-procedural dependency**

```diff
//VUL4J-53 (CVE-2018-1999044)
@@ -204,7 +204,7 @@ void addTo(Calendar c, int i) {
        }

        void setTo(Calendar c, int i) {
-            c.set(field,i-offset);
+            c.set(field,Math.min(i-offset, c.getActualMaximum(field)));
        }

        void clear(Calendar c) {
```
Analysis:
`Math.min(i - offset, c.getActualMaximum(field))` is used to ensure that calculations or value settings do not exceed the allowed boundaries, the system can prevent endless loops. However, for learning based methods, they don't know the restriction, and also which function could be called to fix it, i.e., lack understanding for code dependency and logic.

**3. Single Line Change does not mean simple change**

```diff
//Vul4J-54, CVE-2017-1000355
@@ -145,6 +145,9 @@ private void init() {
        // list up types that should be marshalled out like a value, without referential integrity tracking.
        addImmutableType(Result.class);

+        denyTypes(new Class[] { void.class, Void.class });

        registerConverter(new RobustCollectionConverter(getMapper(),getReflectionProvider()),10);
        registerConverter(new RobustMapConverter(getMapper()), 10);
        registerConverter(new ImmutableMapConverter(getMapper(),getReflectionProvider()),10);
```

Analysis: Feeding XStream with specially crafted XML can cause the JVM to crash, leading to a Denial of Service DoS attack. This occurs when the XML contains type information that directs XStream to create an instance of the **primitive void** type, which cannot have instances. So the fix is to explicitly blocks XStream from handling `void.class` and `Void.class`.  Though the fix is only one line, if the **root cause** of this vulnerability is unclear, even though feed LLMs with vulnerable function, fix location, and CWE type, it's still not helpful.

Other examples that single line change with complex spec/logic/depedency

```diff
//VUL4J-57 (CVE-2018-1000089)
@@ -63,6 +60,7 @@ public boolean start() throws Exception {
        if (item == null) {
            throw new AbortException("No item named " + job + " found");
        }
+        item.checkPermission(Item.BUILD);
        if (step.getWait() && !(item instanceof Job)) {
            // TODO find some way of allowing ComputedFolders to hook into the listener code
            throw new AbortException("Waiting for non-job items is not supported");
```
```diff
//VUL4J-62 (CVE-2018-18389)
@@ -232,6 +232,9 @@ private LdapContext getLdapContextUsingStartTls( LdapContextFactory ldapContextF
            ctx.addToEnvironment( Context.SECURITY_PRINCIPAL, principal );
            ctx.addToEnvironment( Context.SECURITY_CREDENTIALS, credentials );

+            // do a lookup of the user to trigger authentication
+            ctx.lookup( principal.toString() );
+
            return ctx;
        }
        catch ( IOException e )
```

**4. Not straightforward control structures changes**

```diff
//VUL4J-63 CVE-2018-1000615
@@ -50,20 +50,30 @@ public static void versionMatch(String version) {
     * @return an int number
     */
    public static int versionCompare(String fromVersion, String toVersion) {
+        if (fromVersion == null || toVersion == null) {
+            return -1;
+        }
        String[] fromArr = fromVersion.split("\\.");
        String[] toArr = toVersion.split("\\.");
-        int fromFirst = Integer.parseInt(fromArr[0]);
-        int fromMiddle = Integer.parseInt(fromArr[1]);
-        int fromEnd = Integer.parseInt(fromArr[2]);
-        int toFirst = Integer.parseInt(toArr[0]);
-        int toMiddle = Integer.parseInt(toArr[1]);
-        int toEnd = Integer.parseInt(toArr[2]);
-       if (fromFirst - toFirst != 0) {
-            return fromFirst - toFirst;
-        } else if (fromMiddle - toMiddle != 0) {
-            return fromMiddle - toMiddle;
-        } else {
-            return fromEnd - toEnd;
+        if (fromArr.length != 3 || toArr.length != 3) {
+            return -1;
+        }
+        try {
+            int fromFirst = Integer.parseInt(fromArr[0]);
+            int fromMiddle = Integer.parseInt(fromArr[1]);
+            int fromEnd = Integer.parseInt(fromArr[2]);
+            int toFirst = Integer.parseInt(toArr[0]);
+            int toMiddle = Integer.parseInt(toArr[1]);
+            int toEnd = Integer.parseInt(toArr[2]);
+            if (fromFirst - toFirst != 0) {
+                return fromFirst - toFirst;
+            } else if (fromMiddle - toMiddle != 0) {
+                return fromMiddle - toMiddle;
+            } else {
+                return fromEnd - toEnd;
+            }
+        } catch (NumberFormatException nfe) {
+            return -1;
        }
    }
}   
```

```diff
@@ -271,11 +271,6 @@ public void startElement(QName element, XMLAttributes attributes, Augmentations

			boolean isStyle = "style".endsWith(element.localpart);

-			if (isStyle) {
-				this.operations.push(Ops.CSS);
-				cssContent = new StringBuffer();
-				cssAttributes = attributes;
-			} else {
				// validate all attributes, we need to do this now to find out
				// how to deal with the element
				boolean removeTag = false;
@@ -352,6 +347,10 @@ public void startElement(QName element, XMLAttributes attributes, Augmentations

				if (removeTag) {
					this.operations.push(Ops.REMOVE);
+				} else if (isStyle) {
+					this.operations.push(Ops.CSS);
+					cssContent = new StringBuffer();
+					cssAttributes = validattributes;
				} else if (filterTag) {
					this.operations.push(Ops.FILTER);
				} else {
```
## Summarized cases that non-learning-based methods can repair

> The types of vulnerabilities that can be repaired by non-learning-based methods depend on the design of these methods, which are more transparent than learning-based methods. Here, we only list some cases where non-learning-based methods can repair vulnerabilities but learning-based methods cannot.

**1. Dependent with Macros, global variables, unobtainable structure members, etc.**

- Case 1: CVE-2012-2806

```diff
@@ -323,14 +323,15 @@ get_sos (j_decompress_ptr cinfo)

  /* Collect the component-spec parameters */

-  for (i = 0; i < cinfo->num_components; i++)
+  for (i = 0; i < MAX_COMPS_IN_SCAN; i++)
    cinfo->cur_comp_info[i] = NULL;

  for (i = 0; i < n; i++) {
    INPUT_BYTE(cinfo, cc, return FALSE);
    INPUT_BYTE(cinfo, c, return FALSE);

-    for (ci = 0, compptr = cinfo->comp_info; ci < cinfo->num_components;
+    for (ci = 0, compptr = cinfo->comp_info;
+	    ci < cinfo->num_components && ci < MAX_COMPS_IN_SCAN;
	    ci++, compptr++) {
      if (cc == compptr->component_id && !cinfo->cur_comp_info[ci])
	goto id_found;
```

Analysis: The root cause of the vulnerability is the use of `cinfo->num_components` as the loop boundary without validation. This value, provided by the input JPEG file, is potentially be set to an arbitrary number. Consequently, the loop might iterate beyond the bounds of allocated memory, leading to a heap-based buffer overflow. To repair this vulnerability, it needs to take the macro `MAX_COMPS_IN_SCAN` into consideration, which defines the maxium number of components the program can safely handle.  Changing the loop condition accordingly prevents overflow. While learning-based methods miss such critical macros. The non-learning based methods can synthesize correct patch with the correct constraint extracted during fuzzing. 

Case-2: [CVE-2016-8691](https://github.com/jasper-software/jasper/commit/d8c2604cd438c41ec72aff52c16ebd8183068020)

```diff
@@ -512,6 +512,16 @@ static int jpc_siz_getparms(jpc_ms_t *ms, jpc_cstate_t *cstate,
			jas_free(siz->comps);
			return -1;
		}
+		if (siz->comps[i].hsamp == 0 || siz->comps[i].hsamp > 255) {
+			jas_eprintf("invalid XRsiz value %d\n", siz->comps[i].hsamp);
+			jas_free(siz->comps);
+			return -1;
+		}
+		if (siz->comps[i].vsamp == 0 || siz->comps[i].vsamp > 255) {
+			jas_eprintf("invalid YRsiz value %d\n", siz->comps[i].vsamp);
+			jas_free(siz->comps);
+			return -1;
+		}
		siz->comps[i].sgnd = (tmp >> 7) & 1;
		siz->comps[i].prec = (tmp & 0x7f) + 1;
	}
```

Analysis: The root cause of the vulnerability lies in the lack of boundary checks for the horizontal sampling factor (hsamp) and vertical sampling factor (vsamp). If there is not such check, the value could be 0 or greater than 255, may leading to division by zero and application crash. To fix this, the member in structure `jpc_siz_t`and `jpc_sizcomp_t` must be considered, otherwise, it is possible for a correct repair. For learning based methods, only with a vulnerable function takes no effect. For non-learning based methods, e.g., Vulnfix, according to fuzzing, to extract invariant, constraint, which take the necessary dependency into consideration, performing a correct repair.

Case-3: [CVE-2018-14498](https://github.com/libjpeg-turbo/libjpeg-turbo/commit/9c78a04df4e44ef6487eee99c4258397f4fdca55)

```diff
@@ -72,6 +72,7 @@ typedef struct _bmp_source_struct {
  JDIMENSION row_width;         /* Physical width of scanlines in file */

  int bits_per_pixel;           /* remembers 8- or 24-bit format */
+  int cmap_length;              /* colormap length */

  boolean use_inversion_array;  /* TRUE = preload the whole image, which is
                                   stored in bottom-up order, and feed it to
@@ -155,6 +156,7 @@ get_8bit_row(j_compress_ptr cinfo, cjpeg_source_ptr sinfo)
{
  bmp_source_ptr source = (bmp_source_ptr)sinfo;
  register JSAMPARRAY colormap = source->colormap;
+  int cmaplen = source->cmap_length;
  JSAMPARRAY image_ptr;
  register int t;
  register JSAMPROW inptr, outptr;
@@ -178,11 +180,15 @@ get_8bit_row(j_compress_ptr cinfo, cjpeg_source_ptr sinfo)
  if (cinfo->in_color_space == JCS_GRAYSCALE) {
    for (col = cinfo->image_width; col > 0; col--) {
      t = GETJSAMPLE(*inptr++);
+      if (t >= cmaplen)
+        ERREXIT(cinfo, JERR_BMP_OUTOFRANGE);
      *outptr++ = colormap[0][t];
    }
```

This is the fix on structure, and also add condition check in the file, which is much more complex, Extractfix could generate plausible patch, though not totally same. While learning based methods, could not.

## Summarized cases that non-learning-based methods cannot repair 

**Case-1: Gnubug-26545**

```diff
@@ -287,7 +287,7 @@ fillpattern (int type, unsigned char *r, size_t size)
  r[0] = (bits >> 4) & 255;
  r[1] = (bits >> 8) & 255;
  r[2] = bits & 255;
-  for (i = 3; i < size / 2; i *= 2)
+  for (i = 3; i <= size / 2; i *= 2)
    memcpy (r + i, r, i);
  if (i < size)
    memcpy (r + i, r, size - i);
```
non learning based methods fix this, but learning based method could repair. 

**Case-2: CVE-2016-9273**

```diff
@@ -63,6 +63,15 @@ TIFFNumberOfStrips(TIFF* tif)
	TIFFDirectory *td = &tif->tif_dir;
	uint32 nstrips;

+    if( td->td_nstrips )
+        return td->td_nstrips;

	nstrips = (td->td_rowsperstrip == (uint32) -1 ? 1 :
	     TIFFhowmany_32(td->td_imagelength, td->td_rowsperstrip));
	if (td->td_planarconfig == PLANARCONFIG_SEPARATE)
```
In this case, the vulnerability fix is a single-hunk fix and only has two lines of code addition. However, it **cannot be repaired by both learning and non-learning methods**. The root of the vulnerability lies in the reliance on the cached value of `td->td_nstrips`, This value is calculated when the strip count is first needed, based on the image's length and the rows per strip. However, if the structure of the image changes afterward in another function, the cached value becomes outdated, leading to inconsistencies. The vulnerability emerges because there is no mechanism to ensure that the cached. `td->td_nstrips` value is updated when the underlying image structure changes. For learning-based methods, it has no context, no information about the `td` member, and unclear about the root cause of this vulnerability, so it's hard to repair. For non-learning based methods, wrong constraints, and wrong localization lead to no successul repair. As analyzed in this case, although the change is 2 lines of code, it still has a complex logic.




## Summary
1. Though very simple changes, the vulnerability logic could be very complex. So in this case, it is hard to fix by both learning and non-learning based methods. The focus should be on how to determine the root cause of the vulnerability, and for constraints, invariants inference, etc, instead of totally rely on learning based methods in the first step, because in most situation, they only have limited context.
2. The vulnerability on C/C++ in more on memory bugs, however, for Java, it's a memory-safe language, most of its vulnerability are on the application-layer, could have more logic vulnerability, which has low RSR(as shown in our paper).
3. In AVR, there is currently no method that has an absolute advantage. 


## Hybrid approach will enhance AVR

For exmaple, `CVE-2022-1674`
This vulnerability could not be repair by SOTA NPDs repair tool [CONCH](https://www.usenix.org/system/files/usenixsecurity24-xing-yunlong.pdf) due to *Unobtainable Member*, when directly feed this into LLM with CWE type, fix location, vulnerable function, it could not be repaired, either. However, when given the structure of regmatch_T. LLM(specifically, gpt-4) could perform a correct repair.  So in this case, the thing we should do is to use like program analysis to obtain its structure, and together with LLM to fix. Similar cases that we mentioned above could also be repaired using this.

```diff
@@ -2932,7 +2932,7 @@ buflist_match(

    // First try the short file name, then the long file name.
    match = fname_match(rmp, buf->b_sfname, ignore_case);
-    if (match == NULL)
+    if (match == NULL && rmp->regprog != NULL)
	match = fname_match(rmp, buf->b_ffname, ignore_case);

    return match;
```

Except static program analysis, other dynamic analysis could also be used, like fuzzing, we could extract the constraint from the trace. 

Also, other information, e.g., specifications, code comments may also be helpful to fix the vulnerability(Please see what we discussed in paper in Section 5.2).
