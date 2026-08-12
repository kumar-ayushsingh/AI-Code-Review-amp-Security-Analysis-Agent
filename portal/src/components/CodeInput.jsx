import React, { useState, useRef } from "react";
import styles from "./CodeInput.module.css";

export default function CodeInput({ onAnalyze }) {
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [filename, setFilename] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  };

  const handleFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      setCode(e.target.result);
      setFilename(file.name);
      if (file.name.endsWith(".java")) {
        setLanguage("java");
      } else {
        setLanguage("python");
      }
    };
    reader.readAsText(file);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!code.trim()) return;
    onAnalyze(code, language, filename || "pasted_code.py");
  };

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Submit Code for Analysis</h1>
      <p className={styles.subtitle}>
        Upload a file or paste your Python/Java code below to run it through our AI code review and security agents.
      </p>

      <div
        className={`${styles.dropzone} ${isDragging ? styles.dragging : ""}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          type="file"
          accept=".py,.java"
          ref={fileInputRef}
          onChange={handleFileChange}
          style={{ display: "none" }}
        />
        <svg
          className={styles.uploadIcon}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
        <p>Drag and drop a .py or .java file here, or click to browse</p>
      </div>

      <form onSubmit={handleSubmit} className={styles.form}>
        <div className={styles.controls}>
          <input
            type="text"
            placeholder="Filename (optional)"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            className={styles.input}
          />
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            className={styles.select}
          >
            <option value="python">Python</option>
            <option value="java">Java</option>
          </select>
        </div>

        <textarea
          className={styles.textarea}
          placeholder="Or paste your code here..."
          value={code}
          onChange={(e) => setCode(e.target.value)}
          required
        />

        <button type="submit" className={styles.button} disabled={!code.trim()}>
          Analyze Code
        </button>
      </form>
    </div>
  );
}
