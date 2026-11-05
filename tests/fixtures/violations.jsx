import React from "react";
import "./theme.css";

export default function Page({ items, id, label }) {
  return (
    <main>
      <h1>Shop</h1>
      <h3>Skipped level</h3>
      <img src="a.png" />
      <img src="b.png" alt="image" />
      <img src={src} alt={desc} />
      <a href="/x"></a>
      <a href="/y">Click here</a>
      <button></button>
      <button aria-label={label}></button>
      <input type="text" id="name" />
      <input type="text" id={id} />
      <label htmlFor="other">Other</label>
      <p style={{ color: "#aaa", backgroundColor: "#fff" }}>Low contrast</p>
      <p style={{ fontSize: 9 }}>Tiny</p>
      <ul>{items.map((i) => (<li key={i}><a href={`/i/${i}`}>{i}</a></li>))}</ul>
      <div role="button" aria-labelledby="gone" tabIndex={3}>x</div>
      const x: Array<string> = [];
    </main>
  );
}
