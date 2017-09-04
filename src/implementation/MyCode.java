package implementation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import javax.security.auth.x500.X500Principal;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Target;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	private static final String LOCAL_KEYSTORE_LOCATION = "local\\local.p12";
	private static final String MY_PASSWORD = "vesic";
	private static final String KEY_ALGORITHM = "EC";
	private static final String KEYSTORE_INSTANCE_NAME = "PKCS12";
	private static final String CERTIFICATE_INSTANCE = "X.509";
	private static final String BASIC_CONSTRAINTS_OID = "2.5.29.19";
	private static final String SUBJECT_KEY_IDENTIFIERS_OID = "2.5.29.14";
	private static final String SUBJECT_DIRECTORY_ATTRIBUTES_OID = "2.5.29.9";
	private static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";
	private static final String DATE_OF_BIRTH_OID  = "1.3.6.1.5.5.7.9.1";
	private static final String COUNTRY_OF_CITIZENSHIP_OID = "1.3.6.1.5.5.7.9.4";
	private static final String PLACE_OF_BIRTH_OID = "1.3.6.1.5.5.7.9.2";
	private static final String GENDER_OID = "1.3.6.1.5.5.7.9.3";
	
	private static final int ERROR = -1;
	private static final int NOT_SIGNED_CERTIFICATE = 0;
	private static final int SIGNED_CERTIFICATE = 1;
	private static final int IMPORTED_TRUSTED_CERTIFICATE = 2;
	private static final int PEM_ENCODING = 1;
	private static final int DER_ENCODING = 0;
	private static final int CRITICAL_BASIC_CONSTRAINTS = 8; 
	private static final int CRITICAL_KEY_IDENTIFIERS = 0;
	private static final int CRITICAL_SUBJECT_DIRECTORY_ASTRIBUTES = 7;
	
	private String selectedKeyPair=null;
	private PKCS10CertificationRequest certificationRequest;
	private KeyStore localKeyStore;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		// TODO Auto-generated constructor stub
	}
	
	@Override
	public boolean importKeypair(String keypair_name, String file, String password) 
	{
		try 
		{
			KeyStore newKeyStore = KeyStore.getInstance(KEYSTORE_INSTANCE_NAME);
			
			InputStream inputStream = new FileInputStream(file);
			newKeyStore.load(inputStream, password.toCharArray());
			Key key = newKeyStore.getKey(keypair_name, password.toCharArray());
			localKeyStore.setKeyEntry(keypair_name, (PrivateKey)key, MY_PASSWORD.toCharArray(), 
					newKeyStore.getCertificateChain(keypair_name));
			localKeyStore.store(new FileOutputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
			return true;
			
		} catch (FileNotFoundException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	private void ImportKeys(String keypair_name, String file, String password) throws Exception
	{
		// Read Public Key.
		File filePublicKey = new File(file + "public.key");
		InputStream inputStream=new FileInputStream(file);

		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		inputStream.read(encodedPublicKey);
		inputStream.close();
		 
		// Read Private Key.
		File filePrivateKey = new File(file + "private.key");
		inputStream = new FileInputStream(file + "private.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		inputStream.read(encodedPrivateKey);
		inputStream.close();
		 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		 
		KeyPair keyPair = new KeyPair(publicKey, privateKey);
	}
	
	private void ExportKeys(String keypair_name, String file, X509Certificate exportCertificate) throws Exception
	{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				exportCertificate.getPublicKey().getEncoded());
		FileOutputStream outputStream = new FileOutputStream(file + "public.key");
		outputStream.write(x509EncodedKeySpec.getEncoded());
		outputStream.close();
 
		// Store Private Key.
		Key key = localKeyStore.getKey(keypair_name, MY_PASSWORD.toCharArray());
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				((PrivateKey) key).getEncoded());
		 
		outputStream = new FileOutputStream(file + "private.key");
		outputStream.write(pkcs8EncodedKeySpec.getEncoded());
		outputStream.close();
	}
	
	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		try 
		{
			if (!localKeyStore.containsAlias(keypair_name)) return false;
			
			Key key = localKeyStore.getKey(keypair_name, MY_PASSWORD.toCharArray());
			X509Certificate exportCertificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			
			localKeyStore.setKeyEntry(keypair_name, (PrivateKey) key, password.toCharArray(),
					new java.security.cert.Certificate[]{exportCertificate});
			
			FileOutputStream outputStream = new FileOutputStream(file + ".p12");
			localKeyStore.store(outputStream, password.toCharArray());
			return true;
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() 
	{
		try 
		{
			localKeyStore = KeyStore.getInstance(KEYSTORE_INSTANCE_NAME);
			localKeyStore.load(new FileInputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
			return localKeyStore.aliases();
			
		} catch (KeyStoreException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	@Override
	public void resetLocalKeystore() 
	{
		try 
		{
			for (String alias : Collections.list(localKeyStore.aliases()))
			{
				localKeyStore.deleteEntry(alias);
			}
			localKeyStore.store(new FileOutputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
		} catch (KeyStoreException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Override
	public int loadKeypair(String keypair_name) 
	{
		try 
		{
			selectedKeyPair= keypair_name;
			X509Certificate localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			//localKeyStoreCertificate.verify(localKeyStoreCertificate.getPublicKey(), 
			//		access.getPublicKeySignatureAlgorithm());
			ShowCertificateInformation(localKeyStoreCertificate);
			if(false == localKeyStore.isKeyEntry(keypair_name) || localKeyStoreCertificate.getBasicConstraints()!=-1)
			{
				return IMPORTED_TRUSTED_CERTIFICATE;
			}
			if(localKeyStore.getCertificateChain(keypair_name).length > 1) 
			{
				return SIGNED_CERTIFICATE;
			}
			if (!localKeyStore.containsAlias(keypair_name)) 
			{
				return ERROR;
			}			
			return NOT_SIGNED_CERTIFICATE;
			
		} catch (Exception e)
		{
			return ERROR;
		}
	}
	
	private void ShowCertificateInformation(X509Certificate localKeyStoreCertificate) throws ParseException
	{
		
		access.setSubject(localKeyStoreCertificate.getSubjectX500Principal().getName());
		access.setIssuer(localKeyStoreCertificate.getIssuerX500Principal().getName());
		access.setSerialNumber(localKeyStoreCertificate.getSerialNumber().toString());
		access.setNotBefore(localKeyStoreCertificate.getNotBefore());
		access.setNotAfter(localKeyStoreCertificate.getNotAfter());
		access.setVersion(localKeyStoreCertificate.getVersion()-1);
		access.setIssuerSignatureAlgorithm(localKeyStoreCertificate.getSigAlgName());
		access.setPublicKeyAlgorithm(localKeyStoreCertificate.getSigAlgName());
		access.setPublicKeyECCurve(localKeyStoreCertificate.getSigAlgName());
		access.setSubjectSignatureAlgorithm(localKeyStoreCertificate.getSigAlgName());
		
		if (localKeyStoreCertificate.getCriticalExtensionOIDs()!=null)
		{
			access.setCritical(CRITICAL_BASIC_CONSTRAINTS, 
					localKeyStoreCertificate.getCriticalExtensionOIDs().contains(BASIC_CONSTRAINTS_OID));
			
			access.setCritical(CRITICAL_KEY_IDENTIFIERS, 
			    	localKeyStoreCertificate.getCriticalExtensionOIDs().contains(SUBJECT_KEY_IDENTIFIERS_OID) || 
			    	localKeyStoreCertificate.getCriticalExtensionOIDs().contains(AUTHORITY_KEY_IDENTIFIER_OID));
			
			access.setCritical(CRITICAL_SUBJECT_DIRECTORY_ASTRIBUTES, 
			    	localKeyStoreCertificate.getCriticalExtensionOIDs().contains(SUBJECT_DIRECTORY_ATTRIBUTES_OID));
		}
		
		int basicConstraints = localKeyStoreCertificate.getBasicConstraints();
		
		if (basicConstraints == -1)
			access.setCA(false); 
		else
		{
			access.setCA(true);
		    access.setPathLen(""+basicConstraints);
		}
		

		byte[] subjectKeyByte = localKeyStoreCertificate.getExtensionValue(SUBJECT_KEY_IDENTIFIERS_OID);
		if (subjectKeyByte!=null){
			byte[] octets = DEROctetString.getInstance(subjectKeyByte).getOctets();
			SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(octets);
			byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();
			String keyIdentifierHex = new String(Hex.encode(keyIdentifier));
			access.setSubjectKeyID(keyIdentifierHex);
		}
		byte[] authorityKeyByte = localKeyStoreCertificate.getExtensionValue(AUTHORITY_KEY_IDENTIFIER_OID);
		if (authorityKeyByte!=null){
			byte[] authoOctets = DEROctetString.getInstance(authorityKeyByte).getOctets();
			AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(authoOctets);
			
			ASN1OctetString ASN1Octet = ASN1OctetString.getInstance(authorityKeyByte);
			AuthorityKeyIdentifier authorKeyIdentifier = AuthorityKeyIdentifier.getInstance(ASN1Octet.getOctets());
			String str = new String(authorityKeyIdentifier.getKeyIdentifier().toString());
			access.setAuthorityKeyID(str);
			access.setAuthorityIssuer(authorityKeyIdentifier.getAuthorityCertIssuer().getNames()[0].getName().toString());
			 
			access.setAuthoritySerialNumber(authorityKeyIdentifier.getAuthorityCertSerialNumber().toString());
			access.setEnabledKeyIdentifiers(false);
		}
		
		byte[] subjectDirectoryBytes = localKeyStoreCertificate.getExtensionValue(SUBJECT_DIRECTORY_ATTRIBUTES_OID);
		if (null!=subjectDirectoryBytes)
		{
			byte[] authoOctets = DEROctetString.getInstance(subjectDirectoryBytes).getOctets();
			SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(authoOctets);
			Vector<Attribute> vector = subjectDirectoryAttributes.getAttributes();
			for (Attribute atr: vector)
			{
				ASN1Set set = atr.getAttrValues();
				switch (atr.getAttrType().getId())
				{
					case DATE_OF_BIRTH_OID:
					{
		        		//ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(set.getObjectAt(0));
		        		//Date date = time.getDate();
		        		//String dateStr = dateF.format(date);
		        		String dateStr = ((ASN1String)set.getObjectAt(0)).getString();
						access.setDateOfBirth(dateStr);
						break;
					}
					case COUNTRY_OF_CITIZENSHIP_OID:
					{
						String citizenship = ((ASN1String)set.getObjectAt(0)).getString();
						access.setSubjectDirectoryAttribute(1, citizenship);
						break;
					}
					case PLACE_OF_BIRTH_OID:
					{
						String placeOfBirth = ((ASN1String)set.getObjectAt(0)).getString();
						access.setSubjectDirectoryAttribute(0 , placeOfBirth);
						break;
					}
					case GENDER_OID:
					{
		        		String gender = ((ASN1String)set.getObjectAt(0)).getString();
						access.setGender(gender);
						break;
					}
				}
			}
		}
		
		
		//access.setSubjectKeyID(subjectKeyID);
		
		//authorityKeyIdentifier.getKeyIdentifier()
		/*
		ASN1InputStream is = new ASN1InputStream(subjectKeyByte); 
        ASN1Sequence seq = (ASN1Sequence) is.readObject(); 
        @SuppressWarnings("deprecation")
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq); 
        SubjectKeyIdentifier subjectKeyIdentifier = new BcX509ExtensionUtils().createSubjectKeyIdentifier(info); 
		
		if (subjectKeyByte!=null)
		{
			SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(
					X509ExtensionUtil.fromExtensionValue(subjectKeyByte));
			
			for (ASN1IdentifierObject id:subjectKeyIdentifier)
			{
			
				access.setEnabledKeyIdentifiers(false);
				access.setAuthorityKeyID(authorityKeyID);
				access.setSubjectKeyID(subjectKeyID);
			}

		}*/
		
		
		//localKeyStoreCertificate
		//access.sets
		//localKeyStoreCertificate
	}
	
	@Override
	public boolean removeKeypair(String keypair_name) {
		try 
		{
			localKeyStore.deleteEntry(keypair_name);
			localKeyStore.store(new FileOutputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
			return true;
		} catch (KeyStoreException e) 
		{
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	private ContentSigner GetContentSigner(String signatureAlgorithm, Key privateKey) 
			throws OperatorCreationException, IOException
	{
		AlgorithmIdentifier signAlgorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder()
				   .find(signatureAlgorithm);
		AlgorithmIdentifier digitalAlgorithmIdentifier = new DefaultDigestAlgorithmIdentifierFinder()
				   .find(signAlgorithmIdentifier);
		return new BcECContentSignerBuilder(signAlgorithmIdentifier, digitalAlgorithmIdentifier)
				   .build(PrivateKeyFactory.createKey(privateKey.getEncoded()));
	}
	
	private X509Certificate SignCertificate(X509v3CertificateBuilder certificateBuilder, Key privateKey,
			String signatureAlgorithm) throws OperatorCreationException, IOException, CertificateException
	{    
		ContentSigner contentSigner = GetContentSigner(signatureAlgorithm,privateKey);
		X509Certificate signedCertificate = new JcaX509CertificateConverter()
				   .getCertificate(certificateBuilder.build(contentSigner));

		return signedCertificate;
	}
	

	private SubjectKeyIdentifier CreateSubjectKeyIdentifier(Key key) throws IOException
	{
		
		ASN1InputStream is = null; 
        try {
            is = new ASN1InputStream(new ByteArrayInputStream(key.getEncoded())); 
            ASN1Sequence seq = (ASN1Sequence) is.readObject(); 
            @SuppressWarnings("deprecation")
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq); 
            return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info); 
        } finally { 
            is.close();
        }
	}
	
	private AuthorityKeyIdentifier CreateAuthorityKeyIdentifier(Key key) throws IOException
	{

		/*SubjectPublicKeyInfo  subjectKeyInfo = SubjectPublicKeyInfoFactory
				.createSubjectPublicKeyInfo((AsymmetricKeyParameter)key);*/
		
		GeneralName genName1 = new GeneralName(GeneralName.directoryName, new DERIA5String(access.getSubject().toString()));
		GeneralNames genNames = new GeneralNames(genName1);
		
		return new AuthorityKeyIdentifier(genNames,  new BigInteger(access.getSerialNumber()));
	}
	
	private SubjectDirectoryAttributes CreateSubjectDirectoryAttributes(X509Certificate localKeyStoreCertificate)
	{
		String dateOfBirth=null, place=null, citizenship=null, gender=null;
		if (localKeyStoreCertificate!=null) 
		{
			byte[] subjectDirectoryBytes = localKeyStoreCertificate.getExtensionValue(SUBJECT_DIRECTORY_ATTRIBUTES_OID);
			if (null!=subjectDirectoryBytes)
			{
				byte[] authoOctets = DEROctetString.getInstance(subjectDirectoryBytes).getOctets();
				SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes.getInstance(authoOctets);
				Vector<Attribute> vector = subjectDirectoryAttributes.getAttributes();
				for (Attribute atr: vector)
				{
					ASN1Set set = atr.getAttrValues();
					switch (atr.getAttrType().getId())
					{
						case DATE_OF_BIRTH_OID:
						{
							dateOfBirth = ((ASN1String)set.getObjectAt(0)).getString();
							break;
						}
						case COUNTRY_OF_CITIZENSHIP_OID:
						{
							citizenship = ((ASN1String)set.getObjectAt(0)).getString();
							break;
						}
						case PLACE_OF_BIRTH_OID:
						{
							place = ((ASN1String)set.getObjectAt(0)).getString();
							break;
						}
						case GENDER_OID:
						{
			        		gender = ((ASN1String)set.getObjectAt(0)).getString();
							break;
						}
					}
				}
			}
		}
		else
		{
			dateOfBirth = access.getDateOfBirth();
			place =access.getSubjectDirectoryAttribute(0); //place
			citizenship = access.getSubjectDirectoryAttribute(1);//citizenship
			gender = access.getGender();
		}
		
	    Vector<Attribute> attributeVector = new Vector<Attribute>();
		if ((dateOfBirth != null && !dateOfBirth.isEmpty())) 
		{
			DERSet derSet = new DERSet(new DERGeneralString(dateOfBirth));
			attributeVector.add(new Attribute(BCStyle.DATE_OF_BIRTH, derSet));
		}
		
		if (place != null && !place.isEmpty()) 
		{
			DERSet derSet = new DERSet(new DERGeneralString(place));
			attributeVector.add(new Attribute(BCStyle.PLACE_OF_BIRTH, derSet));
		}

		if (citizenship != null && !citizenship.isEmpty()) 
		{
			DERSet derSet =new DERSet(new DERGeneralString(citizenship));
			attributeVector.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, derSet));
		}

		if (gender != null && !gender.isEmpty()) 
		{
			DERSet derSet = new DERSet(new DERGeneralString(gender));
			attributeVector.add(new Attribute(BCStyle.GENDER, derSet));
		}

		return  new SubjectDirectoryAttributes(attributeVector);
	}
	
	private void AddExtensions(X509v3CertificateBuilder certificateBuilder, KeyPair keyPair) 
			throws NumberFormatException, IOException, NoSuchAlgorithmException
	{
		//Key Identifier
		if (access.getEnabledKeyIdentifiers())
		{
			certificateBuilder.addExtension(Extension.subjectKeyIdentifier, access.isCritical(CRITICAL_KEY_IDENTIFIERS), 
					CreateSubjectKeyIdentifier(keyPair.getPublic()));

			/*
			GeneralName genName1 = new GeneralName(GeneralName.directoryName, new DERIA5String(access.getSubject().toString()));
			GeneralNames genNames = new GeneralNames(genName1);
			
			AuthorityKeyIdentifier akd= new AuthorityKeyIdentifier(genNames,  new BigInteger(access.getSerialNumber()));
			//.getIssuerX500Principal().getName();
			
			SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
					keyPair.getPublic().getEncoded()).readObject());
				   AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
				   
				   */

		}
		
		//Basic Constraints
		if (!access.getPathLen().isEmpty())
			certificateBuilder.addExtension(Extension.basicConstraints, access.isCritical(CRITICAL_BASIC_CONSTRAINTS),  
					new BasicConstraints(Integer.parseInt(access.getPathLen())));
		else
			certificateBuilder.addExtension(Extension.basicConstraints, access.isCritical(CRITICAL_BASIC_CONSTRAINTS),
					new BasicConstraints(access.isCA()));
		
		if (access.getVersion()>1)
		certificateBuilder.addExtension(Extension.subjectDirectoryAttributes, 
				access.isCritical(CRITICAL_SUBJECT_DIRECTORY_ASTRIBUTES),
				CreateSubjectDirectoryAttributes(null));
	}
	
	@Override
	public boolean saveKeypair(String keypair_name) 
	{
		try 
		{
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(access.getPublicKeyECCurve());
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, new org.bouncycastle.jce.provider.BouncyCastleProvider());
			keyPairGenerator.initialize(spec, new SecureRandom());		// ECParameterSpec / ECGenParameterSpec
			//KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
			
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
					new X500Name(access.getSubject()),
					new BigInteger(access.getSerialNumber()),
					access.getNotBefore(),access.getNotAfter(),
					new X500Name(access.getSubject()),
					keyPair.getPublic());
			
			AddExtensions(certificateBuilder, keyPair);
		
			X509Certificate certificate = SignCertificate(certificateBuilder, (Key)keyPair.getPrivate(),
					access.getPublicKeySignatureAlgorithm());
			
			KeyStore newKeyStore = KeyStore.getInstance(KEYSTORE_INSTANCE_NAME);
			
			newKeyStore.load(null, null);
			
			newKeyStore.setKeyEntry(keypair_name, keyPair.getPrivate(), MY_PASSWORD.toCharArray(), 
					new X509Certificate[] { certificate});
			
			newKeyStore.store(new FileOutputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
			return true;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertIOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}

	@Override
	public String getIssuer(String issuer) {
		try {
			X509Certificate localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(issuer);
			return localKeyStoreCertificate.getIssuerX500Principal().getName();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String issuer) {
		X509Certificate localKeyStoreCertificate;
		try {
			localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(issuer);
			return localKeyStoreCertificate.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public List<String> getIssuers(String issuer) 
	{
		try
		{
			X509Certificate localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(issuer);
			Enumeration aliases = localKeyStore.aliases();
			ArrayList<String> resultingAliases= new ArrayList<String>();
			
			while (aliases.hasMoreElements())
			{
				String alias = (String) aliases.nextElement();
				localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(alias);
				if (localKeyStore.isKeyEntry(alias) && localKeyStoreCertificate.getBasicConstraints()!=-1)
				{
					resultingAliases.add(alias);
				}	
			}
			
			return resultingAliases;
		} catch (Exception e){
			  return null;
		}
	}

	@Override
	public int getRSAKeyLength(String issuer) {
		try {
			X509Certificate localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(issuer);
			return((RSAKey)localKeyStoreCertificate.getPublicKey()).getModulus().bitLength();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return 0;
	}

	@Override
	public boolean importCertificate(File file, String keypair_name) {
		try 
		{
			CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_INSTANCE);        
			X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream(file));
			   
			localKeyStore.setCertificateEntry(keypair_name, certificate);
			localKeyStore.store(new FileOutputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
			return true;
			
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}
	
	@Override
	public boolean exportCertificate(File file, int encoding) {
			try {
				X509Certificate exportCertificate = (X509Certificate) localKeyStore.getCertificate(selectedKeyPair);
				// DER
				if ( DER_ENCODING == encoding )
				{
					FileOutputStream outputStream = new FileOutputStream(new File(file + ".cer"));
					outputStream.write(exportCertificate.getEncoded());
					outputStream.flush();
					outputStream.close();
				}
				else // PEM
				{
					JcaPEMWriter pemWrt = new JcaPEMWriter(new FileWriter(file + ".cer"));
					pemWrt.writeObject(exportCertificate);
					pemWrt.flush();
					pemWrt.close();
				}
				return true;
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		return false;
	}
	
	private void AddExtensions(ExtensionsGenerator extensionsGenerator, X509Certificate localKeyStoreCertificate) throws IOException, NoSuchAlgorithmException
	{
		for (String nonCriticalExtension: localKeyStoreCertificate.getNonCriticalExtensionOIDs())
		{
			switch (nonCriticalExtension) 
			{
				case BASIC_CONSTRAINTS_OID:
				{
					extensionsGenerator.addExtension(Extension.basicConstraints, false,
				    		  new BasicConstraints(localKeyStoreCertificate.getBasicConstraints()));
					break;
				}
				case SUBJECT_KEY_IDENTIFIERS_OID:
				{
					extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, 
								CreateSubjectKeyIdentifier(localKeyStoreCertificate.getPublicKey()));
					break;
				}
				case AUTHORITY_KEY_IDENTIFIER_OID:
				{
					extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, 
								CreateAuthorityKeyIdentifier(localKeyStoreCertificate.getPublicKey()));
					break;
				}
				case SUBJECT_DIRECTORY_ATTRIBUTES_OID:
				{
					extensionsGenerator.addExtension(Extension.subjectDirectoryAttributes, false, 
							CreateSubjectDirectoryAttributes(localKeyStoreCertificate));
					JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
					
					GeneralNames issuerName = new GeneralNames(new GeneralName(GeneralName.dNSName, localKeyStoreCertificate.getIssuerX500Principal().toString()));
					AuthorityKeyIdentifier aki = utils.createAuthorityKeyIdentifier(localKeyStoreCertificate.getPublicKey());
					aki = new AuthorityKeyIdentifier(aki.getKeyIdentifier(), issuerName, localKeyStoreCertificate.getSerialNumber());
						   
					extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, 
							access.isCritical(CRITICAL_KEY_IDENTIFIERS), aki);
					break;
				}
			}
		}
		
		for (String ciritcalExtensions: localKeyStoreCertificate.getCriticalExtensionOIDs())
		{
			switch (ciritcalExtensions) 
			{
				case BASIC_CONSTRAINTS_OID:
				{
					extensionsGenerator.addExtension(Extension.basicConstraints, true,
				    		  new BasicConstraints(localKeyStoreCertificate.getBasicConstraints()));
					break;
				}
				case SUBJECT_KEY_IDENTIFIERS_OID:
				{
					extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, true, 
								CreateSubjectKeyIdentifier(localKeyStoreCertificate.getPublicKey()));
					break;
				}
				case AUTHORITY_KEY_IDENTIFIER_OID:
				{
					extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, true, 
								CreateAuthorityKeyIdentifier(localKeyStoreCertificate.getPublicKey()));
					break;
				}
				case SUBJECT_DIRECTORY_ATTRIBUTES_OID:
				{
					extensionsGenerator.addExtension(Extension.subjectDirectoryAttributes, true, 
							CreateSubjectDirectoryAttributes(localKeyStoreCertificate));
					JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
					
					GeneralNames issuerName = new GeneralNames(new GeneralName(GeneralName.dNSName, localKeyStoreCertificate.getIssuerX500Principal().toString()));
					AuthorityKeyIdentifier aki = utils.createAuthorityKeyIdentifier(localKeyStoreCertificate.getPublicKey());
					aki = new AuthorityKeyIdentifier(aki.getKeyIdentifier(), issuerName, localKeyStoreCertificate.getSerialNumber());
						   
					extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, 
							access.isCritical(CRITICAL_KEY_IDENTIFIERS), aki);
					break;
				}
			}
		}
	}
	
	@Override
	public boolean generateCSR(String keypair_name) {
		try 
		{
			X509Certificate localKeyStoreCertificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			
			PKCS10CertificationRequestBuilder certificationRequestBuilder= new JcaPKCS10CertificationRequestBuilder(
					localKeyStoreCertificate.getSubjectX500Principal(), localKeyStoreCertificate.getPublicKey());
			
			ContentSigner contentSigner = GetContentSigner(access.getPublicKeySignatureAlgorithm(),
					localKeyStore.getKey(keypair_name, MY_PASSWORD.toCharArray()));
			
			ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
			
			AddExtensions(extensionsGenerator, localKeyStoreCertificate);
			
			
			certificationRequestBuilder.addAttribute(
				     PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
				     extensionsGenerator.generate());
			certificationRequest = certificationRequestBuilder.build(contentSigner);
			return true;
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	private void AddExtensions(X509v3CertificateBuilder certificateBuilder)
	{
		org.bouncycastle.asn1.pkcs.Attribute[] attributes = certificationRequest.getAttributes();
		
	    for (int i = 0; i<attributes.length; i++) 
	    {
	    	if (!attributes[i].getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest))
	    	{ 
	    		continue;
	    	}
	    	
	    	Extensions extensions = Extensions.getInstance(attributes[i].getAttrValues().getObjectAt(0));
	    	Enumeration<?> extensionOid = extensions.oids();
	    	while (extensionOid.hasMoreElements()) 
	    	{
	    		try 
	    		{
		    		ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extensionOid.nextElement();
		    		Extension extension = extensions.getExtension(oid);
	    			certificateBuilder.addExtension(oid, extension.isCritical(), extension.getParsedValue());
	    		} catch (CertIOException e1) {
	    			// TODO Auto-generated catch block
	    			e1.printStackTrace();
	    		}
	    	}
	    }
	}
	
	@Override
	public boolean signCertificate(String issuer, String algorithm) {
		try 
		{
			X509Certificate issuerCertificate = (X509Certificate) localKeyStore.getCertificate(issuer);
			X509Certificate selectedCertificate = (X509Certificate) localKeyStore.getCertificate(selectedKeyPair);
			
			X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
					issuerCertificate.getIssuerX500Principal(),
					selectedCertificate.getSerialNumber(),
					selectedCertificate.getNotBefore(),
					selectedCertificate.getNotAfter(),
					new X500Principal(certificationRequest.getSubject().getEncoded()),
					selectedCertificate.getPublicKey());
			
			AddExtensions(certificateBuilder);
			
			ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(
					(PrivateKey) localKeyStore.getKey(issuer, MY_PASSWORD.toCharArray()));
			
			X509Certificate signedCertificate = new JcaX509CertificateConverter()
					   .getCertificate(certificateBuilder.build(contentSigner));
			
			
			
			localKeyStore.setKeyEntry(selectedKeyPair, 
					localKeyStore.getKey(selectedKeyPair, MY_PASSWORD.toCharArray()), 
					MY_PASSWORD.toCharArray(), 
					new X509Certificate[] { signedCertificate, issuerCertificate});
			
			localKeyStore.store(new FileOutputStream(LOCAL_KEYSTORE_LOCATION), MY_PASSWORD.toCharArray());
			
			//SignCertificate(certificateBuilder, (PrivateKey)key, algorithm);
			
			return true;
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

}
