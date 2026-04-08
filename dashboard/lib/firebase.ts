import { initializeApp, getApps } from "firebase/app";
import {
  getAuth,
  GoogleAuthProvider,
  GithubAuthProvider,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from "firebase/auth";
import {
  getFirestore,
  collection,
  doc,
  setDoc,
  addDoc,
  getDocs,
  query,
  orderBy,
  limit,
  serverTimestamp,
  type Timestamp,
} from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyALFQ8T8hWA-XXddsKwZsVLgB0gc9PgjLo",
  authDomain: "fathom-31aec.firebaseapp.com",
  projectId: "fathom-31aec",
  storageBucket: "fathom-31aec.firebasestorage.app",
  messagingSenderId: "596564155078",
  appId: "1:596564155078:web:85bc165387813a901cd5c7",
  measurementId: "G-5B1JKRFF09",
};

// Singleton — avoid re-initializing on hot reload
const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

// ── Auth providers ────────────────────────────────────────────────────────────
export const googleProvider = new GoogleAuthProvider();
export const githubProvider = new GithubAuthProvider();

export async function signInWithGoogle(): Promise<User> {
  const result = await signInWithPopup(auth, googleProvider);
  return result.user;
}

export async function signInWithGithub(): Promise<User> {
  const result = await signInWithPopup(auth, githubProvider);
  return result.user;
}

export async function signOutUser(): Promise<void> {
  await signOut(auth);
}

export { onAuthStateChanged, type User };

// ── Firestore chat history ────────────────────────────────────────────────────

export interface ChatMessage {
  id?: string;
  role: "user" | "assistant";
  content: string;
  ts: Timestamp | null;
  sessionId: string;
  sampleSha256?: string;
  tags?: string[];
}

export interface ChatSession {
  id?: string;
  sessionId: string;
  sampleSha256?: string;
  sampleName?: string;
  createdAt: Timestamp | null;
  messageCount: number;
  lastMessage: string;
}

/** Save a chat message to Firestore under the user's collection. */
export async function saveChatMessage(
  userId: string,
  sessionId: string,
  role: "user" | "assistant",
  content: string,
  sampleSha256?: string,
): Promise<void> {
  try {
    await addDoc(collection(db, "users", userId, "chatMessages"), {
      role,
      content: content.slice(0, 4000), // Firestore 1MB doc limit safety
      sessionId,
      sampleSha256: sampleSha256 || "",
      ts: serverTimestamp(),
    });
  } catch (e) {
    console.warn("[Firebase] saveChatMessage failed:", e);
  }
}

/** Save/update a chat session record. */
export async function saveChatSession(
  userId: string,
  sessionId: string,
  sampleName: string,
  sampleSha256: string,
  lastMessage: string,
  messageCount: number,
): Promise<void> {
  try {
    const ref = doc(db, "users", userId, "chatSessions", sessionId);
    await setDoc(
      ref,
      {
        sessionId,
        sampleName,
        sampleSha256,
        lastMessage: lastMessage.slice(0, 200),
        messageCount,
        updatedAt: serverTimestamp(),
      },
      { merge: true },
    );
  } catch (e) {
    console.warn("[Firebase] saveChatSession failed:", e);
  }
}

/** Load recent chat messages for a session. */
export async function loadChatMessages(
  userId: string,
  sessionId: string,
  maxMessages = 50,
): Promise<ChatMessage[]> {
  try {
    const q = query(
      collection(db, "users", userId, "chatMessages"),
      orderBy("ts", "asc"),
      limit(maxMessages),
    );
    const snap = await getDocs(q);
    return snap.docs
      .map((d) => ({ id: d.id, ...d.data() } as ChatMessage))
      .filter((m) => m.sessionId === sessionId);
  } catch (e) {
    console.warn("[Firebase] loadChatMessages failed:", e);
    return [];
  }
}

/** Load all chat sessions for a user (for history sidebar). */
export async function loadChatSessions(
  userId: string,
  maxSessions = 20,
): Promise<ChatSession[]> {
  try {
    const q = query(
      collection(db, "users", userId, "chatSessions"),
      orderBy("updatedAt", "desc"),
      limit(maxSessions),
    );
    const snap = await getDocs(q);
    return snap.docs.map((d) => ({ id: d.id, ...d.data() } as ChatSession));
  } catch (e) {
    console.warn("[Firebase] loadChatSessions failed:", e);
    return [];
  }
}
