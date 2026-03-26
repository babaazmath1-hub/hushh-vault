async function addMember(){
  const name = document.getElementById('mn').value.trim();
  const email = document.getElementById('me').value.trim();
  const level = parseInt(document.getElementById('ml').value);

  if(!name || !email){
    notif('Name and email required','e');
    return;
  }

  const id = "M" + Math.floor(Math.random() * 10000);

  const res = await fetch(`${API}/members`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      id,
      name,
      email,
      level,
      status: "active",
      joined: new Date().toISOString()
    })
  });

  if(res.ok){
    notif("Member added ✅", "s");
    closeModal();
    loadMembers();
  } else {
    notif("Error adding member ❌", "e");
  }
}