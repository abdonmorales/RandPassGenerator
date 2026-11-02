package gov.nsa.ia.pass;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.WindowConstants;

import gov.nsa.ia.util.KeyUnwrapper;
import gov.nsa.ia.util.KeyWrapper;

/**
 * Swing graphical user interface for RandPassGenerator.  It offers the
 * same generation features as the command line (passwords, passphrases,
 * and raw hexadecimal keys, with optional key encryption) plus decryption
 * of encrypted key files.  The interface uses the Nimbus look and feel.
 *
 * A single RandPassGenerator (and therefore a single DRBG) is created in
 * the background when the window opens, and reused for every generation
 * request.  All generation and encryption work runs off the Swing event
 * dispatch thread, one request at a time.
 */
public class RandPassGeneratorGUI extends JFrame {

    private static final long serialVersionUID = 1L;

    private static final String TYPE_PASSWORDS = "Passwords";
    private static final String TYPE_PASSPHRASES = "Passphrases";
    private static final String TYPE_KEYS = "Hex Keys";

    /** Largest strength the 192-bit DRBG will accept (see RandPassGenerator). */
    private static final int MAX_STRENGTH = RandManager.DRBG_STRENGTH * 2;

    private volatile RandPassGenerator rpg;
    private final List<String> jobMessages = new CopyOnWriteArrayList<String>();
    private boolean busy = false;

    // generation type
    private final JRadioButton passwordsRadio = new JRadioButton(TYPE_PASSWORDS, true);
    private final JRadioButton passphrasesRadio = new JRadioButton(TYPE_PASSPHRASES);
    private final JRadioButton keysRadio = new JRadioButton(TYPE_KEYS);

    // common settings
    private final JSpinner countSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 10000, 1));
    private final JSpinner strengthSpinner =
	new JSpinner(new SpinnerNumberModel(RandPassGenerator.DEFAULT_STRENGTH, 1, MAX_STRENGTH, 8));

    // chunk formatting (passwords and keys)
    private final JCheckBox chunkCheck = new JCheckBox("Split into chunks of");
    private final JSpinner chunkSizeSpinner = new JSpinner(new SpinnerNumberModel(4, 1, 1000, 1));
    private final JTextField chunkSepField = new JTextField(RandPassGenerator.DEFAULT_CHUNK_SEPARATOR, 4);

    // password options
    private final JRadioButton charsetDefaultRadio = new JRadioButton("Default character set", true);
    private final JRadioButton charsetPickRadio = new JRadioButton("Choose character classes:");
    private final JRadioButton charsetFileRadio = new JRadioButton("Custom character set file:");
    private final JCheckBox lowerCheck = new JCheckBox("Lowercase (a-z)", true);
    private final JCheckBox upperCheck = new JCheckBox("Uppercase (A-Z)", true);
    private final JCheckBox digitCheck = new JCheckBox("Digits (0-9)", true);
    private final JCheckBox punctCheck = new JCheckBox("Punctuation", false);
    private final JTextField charsetFileField = new JTextField(22);
    private final JButton charsetFileBrowse = new JButton("Browse...");

    // passphrase options
    private final JSpinner wordLenSpinner =
	new JSpinner(new SpinnerNumberModel(RandPassGenerator.MAX_WORD_LEN, RandPassGenerator.MIN_WORD_LEN + 1, 64, 1));
    private final JSpinner upcaseSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 64, 1));
    private final JTextField wordListField = new JTextField(22);
    private final JButton wordListBrowse = new JButton("Browse...");

    // key options
    private final JCheckBox encryptCheck = new JCheckBox("Encrypt each key to a file (KEY_ID.enc)");
    private final JPasswordField encPasswordField = new JPasswordField(22);
    private final JPasswordField encConfirmField = new JPasswordField(22);
    private final JTextField encDirField = new JTextField(System.getProperty("user.dir"), 22);
    private final JButton encDirBrowse = new JButton("Browse...");

    // option cards
    private final CardLayout optionCards = new CardLayout();
    private final JPanel optionPanel = new JPanel(optionCards);

    // output
    private final JTextArea outputArea = new JTextArea(12, 50);
    private final JButton generateButton = new JButton("Generate");
    private final JButton copyButton = new JButton("Copy");
    private final JButton saveButton = new JButton("Save...");
    private final JButton clearButton = new JButton("Clear");

    // decryption
    private final JTextField decFileField = new JTextField(26);
    private final JButton decFileBrowse = new JButton("Browse...");
    private final JPasswordField decPasswordField = new JPasswordField(26);
    private final JButton decryptButton = new JButton("Decrypt");
    private final JTextField decResultField = new JTextField(40);
    private final JTextField decOutFileField = new JTextField(40);

    // status bar
    private final JLabel statusLabel = new JLabel(" ");
    private final JProgressBar progressBar = new JProgressBar();

    /**
     * Create the main window.  Must be called on the event dispatch thread.
     */
    public RandPassGeneratorGUI() {
	super("RandPassGenerator");
	setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
	addWindowListener(new WindowAdapter() {
		@Override
		public void windowClosing(WindowEvent e) {
		    exitApplication();
		}
	    });

	JTabbedPane tabs = new JTabbedPane();
	tabs.addTab("Generate", buildGeneratePanel());
	tabs.addTab("Decrypt Key", buildDecryptPanel());

	JPanel content = new JPanel(new BorderLayout(0, 6));
	content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
	content.add(tabs, BorderLayout.CENTER);
	content.add(buildStatusBar(), BorderLayout.SOUTH);
	setContentPane(content);

	wireListeners();
	updateOptionCard();
	updateEnabledState();

	pack();
	setMinimumSize(getSize());
	setLocationRelativeTo(null);
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    private JComponent buildGeneratePanel() {
	JPanel panel = new JPanel(new BorderLayout(0, 8));
	panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

	// --- top: type + common settings ---
	JPanel top = new JPanel(new GridBagLayout());
	GridBagConstraints c = gbc();

	ButtonGroup typeGroup = new ButtonGroup();
	typeGroup.add(passwordsRadio);
	typeGroup.add(passphrasesRadio);
	typeGroup.add(keysRadio);
	JPanel typeRow = new JPanel();
	typeRow.setLayout(new BoxLayout(typeRow, BoxLayout.X_AXIS));
	typeRow.add(passwordsRadio);
	typeRow.add(Box.createHorizontalStrut(12));
	typeRow.add(passphrasesRadio);
	typeRow.add(Box.createHorizontalStrut(12));
	typeRow.add(keysRadio);

	addRow(top, c, 0, "Generate:", typeRow);
	addRow(top, c, 1, "How many:", countSpinner);
	JPanel strengthRow = new JPanel();
	strengthRow.setLayout(new BoxLayout(strengthRow, BoxLayout.X_AXIS));
	strengthRow.add(strengthSpinner);
	strengthRow.add(Box.createHorizontalStrut(6));
	strengthRow.add(new JLabel("bits (default " + RandPassGenerator.DEFAULT_STRENGTH
				   + ", max " + MAX_STRENGTH + ")"));
	addRow(top, c, 2, "Strength:", strengthRow);
	addRow(top, c, 3, "Format:", buildChunkRow());
	top.setBorder(BorderFactory.createTitledBorder("Settings"));

	// --- middle: type-specific options ---
	optionPanel.add(buildPasswordOptions(), TYPE_PASSWORDS);
	optionPanel.add(buildPassphraseOptions(), TYPE_PASSPHRASES);
	optionPanel.add(buildKeyOptions(), TYPE_KEYS);
	optionPanel.setBorder(BorderFactory.createTitledBorder("Options"));

	JPanel north = new JPanel(new BorderLayout(0, 8));
	north.add(top, BorderLayout.NORTH);
	north.add(optionPanel, BorderLayout.CENTER);

	// --- bottom: output ---
	outputArea.setEditable(false);
	outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
	JScrollPane scroll = new JScrollPane(outputArea);
	scroll.setBorder(BorderFactory.createTitledBorder("Output"));

	JPanel buttons = new JPanel();
	buttons.setLayout(new BoxLayout(buttons, BoxLayout.X_AXIS));
	buttons.add(clearButton);
	buttons.add(Box.createHorizontalStrut(6));
	buttons.add(copyButton);
	buttons.add(Box.createHorizontalStrut(6));
	buttons.add(saveButton);
	buttons.add(Box.createHorizontalGlue());
	buttons.add(generateButton);
	getRootPane().setDefaultButton(generateButton);

	JPanel south = new JPanel(new BorderLayout(0, 6));
	south.add(scroll, BorderLayout.CENTER);
	south.add(buttons, BorderLayout.SOUTH);

	panel.add(north, BorderLayout.NORTH);
	panel.add(south, BorderLayout.CENTER);
	return panel;
    }

    private JComponent buildChunkRow() {
	JPanel row = new JPanel();
	row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
	row.add(chunkCheck);
	row.add(Box.createHorizontalStrut(4));
	row.add(chunkSizeSpinner);
	row.add(Box.createHorizontalStrut(6));
	row.add(new JLabel("characters, separated by"));
	row.add(Box.createHorizontalStrut(6));
	row.add(chunkSepField);
	row.add(Box.createHorizontalStrut(6));
	row.add(new JLabel("(passwords and keys)"));
	row.add(Box.createHorizontalGlue());
	return row;
    }

    private JComponent buildPasswordOptions() {
	JPanel p = new JPanel(new GridBagLayout());
	GridBagConstraints c = gbc();

	ButtonGroup g = new ButtonGroup();
	g.add(charsetDefaultRadio);
	g.add(charsetPickRadio);
	g.add(charsetFileRadio);

	JPanel classes = new JPanel();
	classes.setLayout(new BoxLayout(classes, BoxLayout.X_AXIS));
	classes.add(lowerCheck);
	classes.add(upperCheck);
	classes.add(digitCheck);
	classes.add(punctCheck);

	JPanel fileRow = new JPanel();
	fileRow.setLayout(new BoxLayout(fileRow, BoxLayout.X_AXIS));
	fileRow.add(charsetFileField);
	fileRow.add(Box.createHorizontalStrut(6));
	fileRow.add(charsetFileBrowse);

	c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
	p.add(charsetDefaultRadio, c);
	c.gridy = 1; c.gridwidth = 1;
	p.add(charsetPickRadio, c);
	c.gridx = 1; c.weightx = 1;
	p.add(classes, c);
	c.gridx = 0; c.gridy = 2; c.weightx = 0;
	p.add(charsetFileRadio, c);
	c.gridx = 1; c.weightx = 1;
	p.add(fileRow, c);
	return wrapTop(p);
    }

    private JComponent buildPassphraseOptions() {
	JPanel p = new JPanel(new GridBagLayout());
	GridBagConstraints c = gbc();

	addRow(p, c, 0, "Longest word (letters):", wordLenSpinner);
	JPanel ruc = new JPanel();
	ruc.setLayout(new BoxLayout(ruc, BoxLayout.X_AXIS));
	ruc.add(upcaseSpinner);
	ruc.add(Box.createHorizontalStrut(6));
	ruc.add(new JLabel("letters of each word (0 = off)"));
	addRow(p, c, 1, "Random uppercase first:", ruc);

	JPanel wl = new JPanel();
	wl.setLayout(new BoxLayout(wl, BoxLayout.X_AXIS));
	wl.add(wordListField);
	wl.add(Box.createHorizontalStrut(6));
	wl.add(wordListBrowse);
	wordListField.setToolTipText("File or URL of a word list; leave blank for the built-in list");
	addRow(p, c, 2, "Word list (optional):", wl);
	return wrapTop(p);
    }

    private JComponent buildKeyOptions() {
	JPanel p = new JPanel(new GridBagLayout());
	GridBagConstraints c = gbc();

	c.gridx = 0; c.gridy = 0; c.gridwidth = 2;
	p.add(encryptCheck, c);
	c.gridwidth = 1;
	addRow(p, c, 1, "Password (16+ chars):", encPasswordField);
	addRow(p, c, 2, "Confirm password:", encConfirmField);
	JPanel dir = new JPanel();
	dir.setLayout(new BoxLayout(dir, BoxLayout.X_AXIS));
	dir.add(encDirField);
	dir.add(Box.createHorizontalStrut(6));
	dir.add(encDirBrowse);
	addRow(p, c, 3, "Save encrypted files in:", dir);
	return wrapTop(p);
    }

    private JComponent buildDecryptPanel() {
	JPanel p = new JPanel(new GridBagLayout());
	p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
	GridBagConstraints c = gbc();

	JPanel fileRow = new JPanel();
	fileRow.setLayout(new BoxLayout(fileRow, BoxLayout.X_AXIS));
	fileRow.add(decFileField);
	fileRow.add(Box.createHorizontalStrut(6));
	fileRow.add(decFileBrowse);
	addRow(p, c, 0, "Encrypted key file:", fileRow);
	addRow(p, c, 1, "Password:", decPasswordField);

	JPanel btnRow = new JPanel();
	btnRow.setLayout(new BoxLayout(btnRow, BoxLayout.X_AXIS));
	btnRow.add(Box.createHorizontalGlue());
	btnRow.add(decryptButton);
	c.gridx = 1; c.gridy = 2; c.weightx = 1;
	p.add(btnRow, c);

	decResultField.setEditable(false);
	decResultField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
	decOutFileField.setEditable(false);
	addRow(p, c, 3, "Decrypted key:", decResultField);
	addRow(p, c, 4, "Written to:", decOutFileField);

	JLabel note = new JLabel("<html>The decrypted key is saved next to the encrypted file as "
				 + "<i>FILE</i>_decrypted.txt, the same as the -decrypt command-line option.</html>");
	c.gridx = 0; c.gridy = 5; c.gridwidth = 2; c.weighty = 1;
	c.anchor = GridBagConstraints.NORTHWEST;
	p.add(note, c);
	return p;
    }

    private JComponent buildStatusBar() {
	JPanel bar = new JPanel(new BorderLayout(8, 0));
	progressBar.setIndeterminate(false);
	progressBar.setPreferredSize(new Dimension(120, progressBar.getPreferredSize().height));
	progressBar.setVisible(false);
	bar.add(statusLabel, BorderLayout.CENTER);
	bar.add(progressBar, BorderLayout.EAST);
	return bar;
    }

    private static GridBagConstraints gbc() {
	GridBagConstraints c = new GridBagConstraints();
	c.insets = new Insets(3, 4, 3, 4);
	c.anchor = GridBagConstraints.WEST;
	c.fill = GridBagConstraints.HORIZONTAL;
	return c;
    }

    private static void addRow(JPanel p, GridBagConstraints c, int row, String label, Component field) {
	c.gridx = 0; c.gridy = row; c.gridwidth = 1; c.weightx = 0;
	p.add(new JLabel(label), c);
	c.gridx = 1; c.weightx = 1;
	p.add(field, c);
    }

    private static JComponent wrapTop(JComponent inner) {
	JPanel outer = new JPanel(new BorderLayout());
	outer.add(inner, BorderLayout.NORTH);
	return outer;
    }

    // ------------------------------------------------------------------
    // Behaviour
    // ------------------------------------------------------------------

    private void wireListeners() {
	passwordsRadio.addActionListener(e -> updateOptionCard());
	passphrasesRadio.addActionListener(e -> updateOptionCard());
	keysRadio.addActionListener(e -> updateOptionCard());

	charsetDefaultRadio.addActionListener(e -> updateEnabledState());
	charsetPickRadio.addActionListener(e -> updateEnabledState());
	charsetFileRadio.addActionListener(e -> updateEnabledState());
	chunkCheck.addActionListener(e -> updateEnabledState());
	encryptCheck.addActionListener(e -> updateEnabledState());

	charsetFileBrowse.addActionListener(e -> chooseFile(charsetFileField, false));
	wordListBrowse.addActionListener(e -> chooseFile(wordListField, false));
	encDirBrowse.addActionListener(e -> chooseFile(encDirField, true));
	decFileBrowse.addActionListener(e -> chooseFile(decFileField, false));

	generateButton.addActionListener(e -> startGeneration());
	decryptButton.addActionListener(e -> startDecryption());
	clearButton.addActionListener(e -> outputArea.setText(""));
	copyButton.addActionListener(e -> copyOutput());
	saveButton.addActionListener(e -> saveOutput());
    }

    private String selectedType() {
	if (passphrasesRadio.isSelected()) return TYPE_PASSPHRASES;
	if (keysRadio.isSelected()) return TYPE_KEYS;
	return TYPE_PASSWORDS;
    }

    private void updateOptionCard() {
	optionCards.show(optionPanel, selectedType());
	updateEnabledState();
    }

    private void updateEnabledState() {
	boolean pick = charsetPickRadio.isSelected();
	lowerCheck.setEnabled(pick);
	upperCheck.setEnabled(pick);
	digitCheck.setEnabled(pick);
	punctCheck.setEnabled(pick);

	boolean file = charsetFileRadio.isSelected();
	charsetFileField.setEnabled(file);
	charsetFileBrowse.setEnabled(file);

	boolean chunkable = !passphrasesRadio.isSelected();
	chunkCheck.setEnabled(chunkable);
	chunkSizeSpinner.setEnabled(chunkable && chunkCheck.isSelected());
	chunkSepField.setEnabled(chunkable && chunkCheck.isSelected());

	boolean enc = encryptCheck.isSelected();
	encPasswordField.setEnabled(enc);
	encConfirmField.setEnabled(enc);
	encDirField.setEnabled(enc);
	encDirBrowse.setEnabled(enc);

	boolean ready = rpg != null && !busy;
	generateButton.setEnabled(ready);
	decryptButton.setEnabled(!busy);
    }

    private void setBusy(boolean b, String status) {
	busy = b;
	progressBar.setIndeterminate(b);
	progressBar.setVisible(b);
	setCursor(b ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
	if (status != null) statusLabel.setText(status);
	updateEnabledState();
    }

    private void chooseFile(JTextField target, boolean directories) {
	JFileChooser fc = new JFileChooser();
	String cur = target.getText().trim();
	if (!cur.isEmpty()) {
	    File f = new File(cur);
	    fc.setCurrentDirectory(f.isDirectory() ? f : f.getAbsoluteFile().getParentFile());
	} else {
	    fc.setCurrentDirectory(new File(System.getProperty("user.dir")));
	}
	if (directories) {
	    fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
	}
	if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
	    target.setText(fc.getSelectedFile().getAbsolutePath());
	}
    }

    private void showError(String msg) {
	JOptionPane.showMessageDialog(this, msg, "RandPassGenerator", JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Create the RandPassGenerator (DRBG instantiation and self-tests)
     * in the background.  Generation is disabled until it is ready.
     */
    private void initializeGenerator() {
	setBusy(true, "Initializing random generator and running self-tests...");
	new SwingWorker<RandPassGenerator, Void>() {
	    @Override
	    protected RandPassGenerator doInBackground() {
		PrintWriter sink = new PrintWriter(new StringWriter());
		RandPassGenerator g = new RandPassGenerator(RandPassGenerator.DEFAULT_LOGFILE, sink, false);
		g.setMessageSink(jobMessages::add);
		if (!g.isReady()) {
		    g.close();
		    throw new IllegalStateException("random generator self-tests failed");
		}
		return g;
	    }

	    @Override
	    protected void done() {
		try {
		    rpg = get();
		    setBusy(false, "Ready.  " + RandPassGenerator.VERSION);
		} catch (InterruptedException | ExecutionException ex) {
		    Throwable cause = (ex.getCause() != null) ? ex.getCause() : ex;
		    setBusy(false, "Initialization failed - generation is disabled.");
		    showError("Could not initialize the random generator:\n" + cause.getMessage()
			      + "\n\nSee " + RandPassGenerator.DEFAULT_LOGFILE + " for details.");
		}
	    }
	}.execute();
    }

    /** Parameters for one generation request, captured on the EDT. */
    private static final class Request {
	String type;
	int count;
	int strength;
	int chunkSize;
	String chunkSep;
	String charsets;
	String charsetFile;
	int maxWordLen;
	int upcase;
	URL wordList;
	char[] encPassword;
	File encDir;
    }

    private Request buildRequest() {
	Request r = new Request();
	r.type = selectedType();
	r.count = ((Number) countSpinner.getValue()).intValue();
	r.strength = ((Number) strengthSpinner.getValue()).intValue();

	if (chunkCheck.isSelected() && !TYPE_PASSPHRASES.equals(r.type)) {
	    r.chunkSize = ((Number) chunkSizeSpinner.getValue()).intValue();
	    r.chunkSep = chunkSepField.getText();
	}

	if (TYPE_PASSWORDS.equals(r.type)) {
	    if (charsetPickRadio.isSelected()) {
		StringBuilder sb = new StringBuilder();
		if (lowerCheck.isSelected()) sb.append('a');
		if (upperCheck.isSelected()) sb.append('A');
		if (digitCheck.isSelected()) sb.append('9');
		if (punctCheck.isSelected()) sb.append('.');
		if (sb.length() == 0) {
		    showError("Select at least one character class, or use the default character set.");
		    return null;
		}
		r.charsets = sb.toString();
	    } else if (charsetFileRadio.isSelected()) {
		String path = charsetFileField.getText().trim();
		File f = new File(path);
		if (path.isEmpty() || !f.isFile() || !f.canRead()) {
		    showError("The custom character set file must be a readable file.");
		    return null;
		}
		int unique;
		try {
		    String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		    unique = gov.nsa.ia.gen.CharacterSet.uniqueCharset(content.toCharArray()).length;
		} catch (IOException ex) {
		    showError("Could not read the custom character set file:\n" + ex.getMessage());
		    return null;
		}
		if (unique < 2) {
		    showError("The custom character set file must contain at least two different\n"
			      + "printable characters (it has " + unique + ").");
		    return null;
		}
		r.charsetFile = path;
	    }
	} else if (TYPE_PASSPHRASES.equals(r.type)) {
	    r.maxWordLen = ((Number) wordLenSpinner.getValue()).intValue();
	    r.upcase = ((Number) upcaseSpinner.getValue()).intValue();
	    String wl = wordListField.getText().trim();
	    if (!wl.isEmpty()) {
		try {
		    File f = new File(wl);
		    if (f.isFile()) {
			r.wordList = f.toURI().toURL();
		    } else {
			r.wordList = new URL(wl);
		    }
		} catch (IOException ex) {
		    showError("The word list must be an existing file or a valid URL.");
		    return null;
		}
	    }
	} else {
	    if (r.strength % 8 != 0) {
		showError("Hex key strength must be a multiple of 8 bits (for example 128, 160, or 256).");
		return null;
	    }
	    if (encryptCheck.isSelected() && !RandPassGenerator.isEncryptableKeyStrength(r.strength)) {
		showError("To encrypt keys, the strength must be a multiple of 32 bits\n"
			  + "and at least 64 (for example 128, 160, 192, or 256).");
		return null;
	    }
	    if (encryptCheck.isSelected()) {
		char[] pw = encPasswordField.getPassword();
		char[] confirm = encConfirmField.getPassword();
		boolean match = Arrays.equals(pw, confirm);
		Arrays.fill(confirm, '\0');
		if (pw.length < KeyWrapper.MIN_PASSWORD_LENGTH) {
		    Arrays.fill(pw, '\0');
		    showError("The encryption password must be at least "
			      + KeyWrapper.MIN_PASSWORD_LENGTH + " characters long.\n"
			      + "Tip: generate a password at strength 96 or more to use here.");
		    return null;
		}
		if (!match) {
		    Arrays.fill(pw, '\0');
		    showError("The encryption passwords do not match.");
		    return null;
		}
		File dir = new File(encDirField.getText().trim());
		if (!dir.isDirectory() || !dir.canWrite()) {
		    Arrays.fill(pw, '\0');
		    showError("The folder for encrypted key files must be an existing, writable folder.");
		    return null;
		}
		r.encPassword = pw;
		r.encDir = dir;
		encPasswordField.setText("");
		encConfirmField.setText("");
	    }
	}
	return r;
    }

    private void startGeneration() {
	if (rpg == null || busy) return;
	final Request req = buildRequest();
	if (req == null) return;

	setBusy(true, "Generating " + req.count + " " + req.type.toLowerCase() + "...");
	jobMessages.clear();

	new SwingWorker<String, Void>() {
	    private int cnt = -1;

	    @Override
	    protected String doInBackground() {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		RandPassGenerator g = rpg;
		try {
		    g.setOutputWriter(pw);
		    g.setChunkFormatting(req.chunkSize, req.chunkSep);
		    if (TYPE_PASSWORDS.equals(req.type)) {
			cnt = g.generatePasswords(req.count, req.strength, req.charsets, req.charsetFile);
		    } else if (TYPE_PASSPHRASES.equals(req.type)) {
			cnt = g.generatePassphrases(req.count, req.strength, req.wordList, req.maxWordLen, req.upcase);
		    } else {
			cnt = g.generateKeys(req.count, req.strength, req.encPassword, req.encDir);
		    }
		} finally {
		    if (req.encPassword != null) Arrays.fill(req.encPassword, '\0');
		    g.setChunkFormatting(0, null);
		}
		pw.flush();
		return sw.toString();
	    }

	    @Override
	    protected void done() {
		String out;
		try {
		    out = get();
		} catch (InterruptedException | ExecutionException ex) {
		    Throwable cause = (ex.getCause() != null) ? ex.getCause() : ex;
		    setBusy(false, "Generation failed.");
		    String why;
		    if (TYPE_PASSPHRASES.equals(req.type) && req.wordList != null) {
			why = "The word list could not be used.  Check that it can be read and has\n"
			    + "at least two different words within the chosen word length.";
		    } else if (req.charsetFile != null) {
			why = "The custom character set could not be used.";
		    } else {
			why = "Unexpected error: " + cause;
		    }
		    showError("Failed to generate " + req.type.toLowerCase() + ".\n" + why
			      + "\n\nSee " + RandPassGenerator.DEFAULT_LOGFILE + " for details.");
		    return;
		}
		if (!out.isEmpty()) {
		    outputArea.append(out);
		    outputArea.setCaretPosition(outputArea.getDocument().getLength());
		}
		if (cnt > 0) {
		    String noun = req.type.toLowerCase();
		    if (cnt == 1) noun = noun.substring(0, noun.length() - 1);
		    String done = "Generated " + cnt + " " + noun + " at strength " + req.strength + " bits";
		    if (req.encDir != null) {
			done += ", encrypted to " + req.encDir.getAbsolutePath();
		    }
		    setBusy(false, done + ".");
		} else {
		    setBusy(false, "Failed to generate " + req.type.toLowerCase() + ".");
		    StringBuilder msg = new StringBuilder("Failed to generate " + req.type.toLowerCase() + ".");
		    for (String m : jobMessages) {
			msg.append('\n').append(m);
		    }
		    if (jobMessages.isEmpty() && TYPE_PASSPHRASES.equals(req.type) && req.wordList != null) {
			msg.append("\nCheck that the word list could be read and has usable words.");
		    }
		    msg.append("\n\nSee ").append(RandPassGenerator.DEFAULT_LOGFILE).append(" for details.");
		    showError(msg.toString());
		}
	    }
	}.execute();
    }

    private void startDecryption() {
	if (busy) return;
	String path = decFileField.getText().trim();
	final File encFile = new File(path);
	if (path.isEmpty() || !encFile.isFile() || !encFile.canRead()) {
	    showError("Choose a readable encrypted key file (.enc).");
	    return;
	}
	char[] pwChars = decPasswordField.getPassword();
	if (pwChars.length < KeyWrapper.MIN_PASSWORD_LENGTH) {
	    Arrays.fill(pwChars, '\0');
	    showError("The password must be at least " + KeyWrapper.MIN_PASSWORD_LENGTH + " characters long.");
	    return;
	}
	final String pw = new String(pwChars);
	Arrays.fill(pwChars, '\0');
	decPasswordField.setText("");
	final File outFile = new File(path + "_decrypted.txt");

	decResultField.setText("");
	decOutFileField.setText("");
	setBusy(true, "Decrypting " + encFile.getName() + "...");

	new SwingWorker<String, Void>() {
	    @Override
	    protected String doInBackground() throws IOException {
		if (!KeyUnwrapper.unwrapKeyToFile(pw, encFile, outFile)) {
		    return null;
		}
		return new String(Files.readAllBytes(outFile.toPath()), StandardCharsets.UTF_8);
	    }

	    @Override
	    protected void done() {
		try {
		    String key = get();
		    if (key == null) {
			setBusy(false, "Decryption failed.");
			showError("Could not decrypt " + encFile.getName()
				  + ".\nCheck that the password is correct and the file is a key file "
				  + "encrypted by RandPassGenerator.");
			return;
		    }
		    decResultField.setText(key);
		    decResultField.setCaretPosition(0);
		    decOutFileField.setText(outFile.getAbsolutePath());
		    setBusy(false, "Decrypted key written to " + outFile.getName());
		} catch (InterruptedException | ExecutionException ex) {
		    Throwable cause = (ex.getCause() != null) ? ex.getCause() : ex;
		    setBusy(false, "Decryption failed.");
		    showError("Decryption failed: " + cause);
		}
	    }
	}.execute();
    }

    private void copyOutput() {
	String text = outputArea.getSelectedText();
	if (text == null || text.isEmpty()) text = outputArea.getText();
	if (text.isEmpty()) return;
	Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
	statusLabel.setText("Copied to clipboard.");
    }

    private void saveOutput() {
	String text = outputArea.getText();
	if (text.isEmpty()) {
	    showError("There is no output to save yet.");
	    return;
	}
	JFileChooser fc = new JFileChooser(new File(System.getProperty("user.dir")));
	if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
	File f = fc.getSelectedFile();
	if (f.exists()) {
	    int ok = JOptionPane.showConfirmDialog(this, f.getName() + " already exists.  Replace it?",
						   "RandPassGenerator", JOptionPane.YES_NO_OPTION,
						   JOptionPane.WARNING_MESSAGE);
	    if (ok != JOptionPane.YES_OPTION) return;
	}
	try {
	    Files.write(f.toPath(), text.getBytes(StandardCharsets.UTF_8));
	    statusLabel.setText("Saved output to " + f.getName());
	} catch (IOException ex) {
	    showError("Could not save to " + f + ":\n" + ex.getMessage());
	}
    }

    private void exitApplication() {
	if (busy) {
	    int ok = JOptionPane.showConfirmDialog(this, "An operation is still running.  Quit anyway?",
						   "RandPassGenerator", JOptionPane.YES_NO_OPTION);
	    if (ok != JOptionPane.YES_OPTION) return;
	}
	dispose();
	RandPassGenerator g = rpg;
	rpg = null;
	if (g != null && !busy) {
	    g.close();
	}
	System.exit(0);
    }

    // ------------------------------------------------------------------
    // Startup
    // ------------------------------------------------------------------

    /**
     * Install the Nimbus look and feel, falling back to the platform
     * default if Nimbus is not available.
     */
    static void installNimbus() {
	try {
	    for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
		if ("Nimbus".equals(info.getName())) {
		    UIManager.setLookAndFeel(info.getClassName());
		    return;
		}
	    }
	} catch (Exception e) {
	    // fall through to the default look and feel
	}
    }

    /**
     * Open the graphical interface.  May be called from any thread.
     */
    public static void launch() {
	SwingUtilities.invokeLater(() -> {
		installNimbus();
		RandPassGeneratorGUI gui = new RandPassGeneratorGUI();
		gui.setVisible(true);
		gui.initializeGenerator();
	    });
    }

    public static void main(String[] args) {
	launch();
    }
}
