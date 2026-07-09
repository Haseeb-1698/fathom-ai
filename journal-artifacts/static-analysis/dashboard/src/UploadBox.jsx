import { useState } from "react";
import { useDropzone } from "react-dropzone";
import axios from "axios";

export default function UploadBox() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // when file is dropped/selected
  const onDrop = async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;
    const file = acceptedFiles[0];
    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      // 🚨 make sure FastAPI is running on localhost:8000
      const res = await axios.post("http://localhost:8000/api/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(res.data);
    } catch (err) {
      alert("Upload failed: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const { getRootProps, getInputProps } = useDropzone({ onDrop });

  return (
    <div>
      <div
        {...getRootProps()}
        style={{
          border: "2px dashed #888",
          padding: "2rem",
          textAlign: "center",
          cursor: "pointer",
          borderRadius: "8px",
          background: "#1a1a1a",
          color: "#fff",
        }}
      >
        <input {...getInputProps()} />
        <p>📂 Drag & drop a file here, or click to select</p>
      </div>

      {loading && <p>⏳ Uploading...</p>}

      {result && (
        <pre
          style={{
            marginTop: "1rem",
            padding: "1rem",
            background: "#222",
            color: "lime",
            borderRadius: "6px",
            textAlign: "left",
          }}
        >
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}
